import type Database from "better-sqlite3";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";

import type { MailTransport } from "../config.js";

import { checkLockout, lockoutKeyFor, recordFailure } from "../auth/lockout.js";
import { hashPassword, PasswordPolicyError } from "../auth/password.js";
import {
  consumeEmailVerification,
  EMAIL_VERIFICATION_TTL_HOURS,
  issueEmailVerification,
} from "../auth/verification.js";
import { getApp } from "../db/apps.js";
import { grantTargetId, recordAudit } from "../db/audit-log.js";
import { getDb } from "../db/connection.js";
import { SELF_REGISTRATION_ACTOR, ensureGrant } from "../db/grants.js";
import { createUser, foldUsername, type UserRow } from "../db/users.js";
import { verificationLink, verificationMail } from "../mail/templates.js";
import { sendMail } from "../mail/transport.js";

/**
 * `POST /register` and `GET /verify` — the estate's only anonymous **write**
 * surface.
 *
 * Registered by `app.ts` (which this brief does not touch) as
 * `await app.register(registerRoutes)`. Both paths here are **Fastify-side**:
 * Caddy serves Ward with `handle_path /ward-api/*`, which strips the prefix, so
 * `/verify` here is `GET /ward-api/verify` in a browser — and that is the URL
 * the mail carries. See `mail/templates.ts`.
 *
 * ## The flag is the whole feature
 *
 * Registration is refused unless the named app's `public_registration` is 1,
 * and a new app is **closed until somebody opens it**
 * ([decisions-accounts.md](../../../corpus/wiki/decisions-accounts.md)).
 * Succeeding confers **that app's baseline role and nothing else**: the
 * security boundary of this estate is the grant, not the signup form, so a
 * stranger who registers at `public-resource-map` gets `prm:user` and cannot
 * see that `atrium` exists. Introspection against any other app shows nothing,
 * and there is a test for exactly that.
 *
 * ## Registering does not sign you in
 *
 * No cookie is set and no token is minted. A person who registers goes to the
 * login form like anybody else. This is a deliberate omission rather than a
 * gap: minting a session here would duplicate `routes/auth.ts`'s cookie logic
 * on the one route that anonymous callers can drive, in exchange for saving one
 * form submission.
 *
 * ## An unverified account is a real account
 *
 * `email_verified` starts at 0 and **nothing here blocks sign-in on it**.
 * Whether an unverified person may do anything is the app's business, decided
 * through the baseline role it handed out; Ward does not interpret roles and
 * does not invent a second gate beside them. The practical consequence is worth
 * knowing: a burned or expired verification link is not a lockout — the account
 * works, the address is just not confirmed.
 *
 * ## Rate limiting counts *attempts*, not failures
 *
 * On `/login` the counter means "unexplained failures" and a correct password
 * forgives them. Here it means **attempts**, successful ones included, and
 * nothing ever calls `clearFailures`. That is the difference between throttling
 * credential guessing and throttling account creation: a flood of *successful*
 * registrations is the abuse this endpoint has to survive, so a success cannot
 * buy the next attempt. Five per fifteen minutes per address, sliding.
 *
 * The surface is `"register"`, which holds a budget of its own — a registration
 * flood must not stop people who already have accounts from signing in, and
 * `LockoutSurface` is a closed union precisely so that borrowing `"login"` is a
 * compile error rather than a coupling nobody notices.
 *
 * ## Nothing sensitive travels in a URL — with one deliberate exception
 *
 * `routes/auth.ts` keeps every credential in a POST body because Fastify's
 * default request log line includes `url`, and therefore the query string, at
 * info level. `GET /verify?token=` breaks that rule because it has to be
 * clickable out of a mail client, so the exception is paid for rather than
 * noted: the route is registered in a nested scope whose `req` log serializer
 * **drops the query string entirely** before the "incoming request" line is
 * written. See `verifyLogSerializers` below for why a hook could not do it.
 */

/** The `actor_label` on the audit rows this flow writes as Ward itself. */
const REGISTRATION_ACTOR_LABEL = "registration";

/**
 * Options accepted at registration.
 *
 * Exactly the shape every other route plugin takes: `db` is an optional extra
 * so a test can register against `openDatabase(":memory:")` without the process
 * resolving `WARD_DB_PATH`. Nothing in production passes it.
 */
export interface RegisterRoutesOptions {
  db?: Database.Database;
}

/**
 * The app slug being registered at.
 *
 * Bounded and lower-cased-by-the-schema, but deliberately **not** validated
 * against `SLUG_PATTERN` from the admin routes: this is a lookup key, the
 * lookup either finds a row or does not, and a stricter pattern here would only
 * change which of two identical refusals a caller gets.
 */
const appSlug = z.string().trim().min(1).max(64);

/**
 * A username, with the same rule the console applies when the owner issues an
 * account (`routes/admin/accounts.ts`).
 *
 * The two must agree. `foldUsername` collapses case and Unicode *form*, so
 * `Alice` and `ａlice` cannot become two accounts; what it does not collapse is
 * whitespace, and two accounts that render identically in the console account
 * list are a way to be granted the wrong person's access by clicking the wrong
 * row. Control characters and non-ASCII space-likes are therefore refused, and
 * runs of visible characters are joined by single spaces or nothing.
 *
 * This matters more on the public path than on the console one: here the name
 * is chosen by a stranger rather than typed by the operator.
 */
const username = z
  .string()
  .trim()
  .min(1)
  .max(256)
  .regex(/^[^\p{C}\p{Zs}]+(?: [^\p{C}\p{Zs}]+)*$/u, {
    message: "username contains a control character or unusual whitespace",
  });

/**
 * The address, **required** — this is the public path, which is the only path
 * where email is collected at all.
 *
 * Trimmed then format-checked, so a pasted address with a trailing space is
 * accepted rather than rejected for a reason nobody can see. `254` is the
 * RFC 5321 maximum for a forward path.
 *
 * **Not lower-cased, and not otherwise normalised.** prm normalises because
 * email *is* its primary key; in Ward the canonical identifier is the username
 * and `users.email` is an optional attribute with no uniqueness constraint at
 * all, so there is nothing for a fold to protect. Folding anyway would be
 * lossy for no benefit: the local part of an address is formally
 * case-sensitive, and Ward would be storing something the person did not type.
 */
const email = z.string().trim().max(254).pipe(z.email());

/**
 * A password with **no length rule here at all** — the same call
 * `routes/admin/accounts.ts` makes on the other account-creating route, for the
 * same reason. `auth/password.ts` owns the policy and throws
 * `PasswordPolicyError` with a stable `code`; this route surfaces that code, so
 * a short password answers `password_too_short` rather than a generic
 * `invalid_request` that tells a new user nothing and puts the real rule in two
 * places that can disagree.
 *
 * That leaves nothing bounding the size of an anonymous caller's password, which
 * would matter if scrypt were reachable with a multi-megabyte string — but
 * Fastify's default body limit is 1 MiB and rejects the request long before this
 * schema sees it. The `MAX_PASSWORD_LENGTH` bound `routes/auth.ts` applies is on
 * the *login* path, where there is no policy error to surface because a
 * too-long password simply cannot match a stored hash.
 */
const password = z.string();

const registerBody = z.object({ app: appSlug, username, email, password });

/**
 * The verification token, as it arrives in the query string.
 *
 * `generateVerificationToken()` is 32 bytes of hex, so the shape is known
 * exactly and anything else is refused before it reaches a hash or the
 * database. That is not security — a 256-bit token needs no help — it is about
 * not running work on garbage.
 */
const verifyQuery = z.object({
  token: z
    .string()
    .trim()
    .regex(/^[0-9a-f]{64}$/, { message: "not a verification token" }),
});

export async function registerRoutes(
  app: FastifyInstance,
  options: RegisterRoutesOptions = {},
): Promise<void> {
  /**
   * Resolved at registration through a **dynamic** import, so that merely
   * importing this module does not run `config.ts`'s validation (and its
   * `process.exit(1)`) — the same reasoning `routes/auth.ts` records.
   *
   * All three are process constants, and resolving them here rather than per
   * request means a misconfigured mail transport or origin is visible at boot
   * instead of at the moment somebody is waiting for a link.
   */
  const { MAIL, WARD_ADMIN_USERNAME, WARD_PUBLIC_ORIGIN } = await import("../config.js");

  /** The break-glass username, folded once. See `usernameIsReserved`. */
  const reservedUsername = foldUsername(WARD_ADMIN_USERNAME);

  /** Lazy, and memoised by `getDb()` itself — never resolved at registration. */
  const database = async (): Promise<Database.Database> => options.db ?? (await getDb());

  /**
   * `POST /register` — create an account at an app that accepts strangers.
   *
   * Body `{ app, username, email, password }`; `201` with the account and what
   * it was granted, or one of the refusals documented on each branch.
   */
  app.post("/register", async (request, reply) => {
    reply.header("cache-control", "no-store");

    const address = lockoutKey(request);

    const gate = checkLockout({ surface: "register", address });
    if (!gate.allowed) {
      return lockedOut(reply, gate.retryAfterSeconds ?? 1);
    }

    const parsed = registerBody.safeParse(request.body);
    if (!parsed.success) {
      /**
       * Deliberately **not** counted against the budget, and deliberately
       * terse. Not counted because a malformed body is a client bug rather than
       * abuse, and counting it means one broken integration throttles its own
       * users out of signing up — the same carve-out `/login` makes. Terse
       * because zod's issue list echoes the submitted values back, and one of
       * them is the password.
       */
      return reply.code(400).send({ error: "invalid_request" });
    }

    const body = parsed.data;

    /**
     * **Counted here, before any work.** Every well-formed attempt spends
     * budget whatever it goes on to answer, so probing for open apps or for
     * taken usernames costs the prober exactly as much as registering does.
     *
     * No `account` on the target: the per-account breakdown exists so that a
     * success can forgive the failures aimed at the account it proved, and this
     * surface never forgives anything. Naming one would only split the counter
     * into buckets nothing reads.
     */
    recordFailure({ surface: "register", address });

    const db = await database();
    const target = getApp(db, body.app);

    /**
     * **One answer for "no such app" and "that app is closed."**
     *
     * Which apps exist is not much of a secret — the slugs are in six
     * deployments' configuration — but there is no reason for the anonymous
     * signup endpoint to be the thing that confirms it, and collapsing the two
     * means the response describes the caller's request rather than Ward's
     * estate.
     *
     * Answered **before** the password is hashed, which is a denial-of-service
     * property rather than a stylistic one: scrypt at Ward's parameters costs
     * 16 MiB and tens of milliseconds, and an endpoint that spends that on a
     * request it was always going to refuse is a CPU amplifier anyone can drive.
     */
    if (target === undefined || target.public_registration !== 1) {
      return registrationClosed(reply);
    }

    /**
     * The schema's CHECK makes an open app without a baseline role impossible,
     * and `setPublicRegistration` refuses to create one. This branch is
     * therefore unreachable — but it is a `500`-shaped surprise if it ever is
     * reached, and the honest handling of "the database says something the
     * schema forbids" is to refuse the registration and say so loudly to the
     * operator rather than to grant `null`.
     */
    const baselineRole = target.baseline_role;
    if (baselineRole === null) {
      request.log.error(
        { app: target.slug },
        "app has public_registration set with no baseline_role; the schema CHECK should " +
          "have made this impossible. Registration refused — fix the row.",
      );
      return registrationClosed(reply);
    }

    /**
     * Hashed before the insert is attempted, on **every** path that gets this
     * far. That is what keeps a username collision from being cheaper than a
     * successful registration: the two differ by one failed INSERT rather than
     * by fifty milliseconds of scrypt, so response time says nothing about
     * whether a name was taken beyond what the status code already says.
     */
    let passwordHash: string;
    try {
      passwordHash = await hashPassword(body.password);
    } catch (error) {
      if (error instanceof PasswordPolicyError) {
        // The stable `code`, never the message — brief 09 renders these.
        return reply.code(400).send({ error: error.code });
      }
      throw error;
    }

    /**
     * The break-glass username is not available to strangers.
     *
     * The superuser has no `users` row and never will
     * ([decisions-admin.md](../../../corpus/wiki/decisions-admin.md)), so an
     * account named after it would not shadow anything at authentication time —
     * `/login` reads the table and `/console/login` reads the environment, and
     * they cannot be confused. What it *would* do is put a row in the console's
     * account list that reads as the operator's own credential, which is the
     * one screen where an operator decides who to trust.
     *
     * Answered as `username_taken`, byte-identical to a genuine collision, so
     * this does not turn `/register` into a way to discover
     * `WARD_ADMIN_USERNAME`: a prober cannot tell "that name is the superuser's"
     * from "somebody already has that name".
     */
    if (foldUsername(body.username) === reservedUsername) {
      return usernameTaken(reply);
    }

    /**
     * One transaction: the account, its single grant, the verification token,
     * and the two audit rows. Either a registered account exists with exactly
     * what registration confers, or nothing happened.
     *
     * `createUser` throws on a taken username rather than this code checking
     * first, because a SELECT-then-INSERT has a race between the two statements
     * and the UNIQUE constraint on `username_folded` does not. Collisions are
     * the *ordinary* case on this endpoint, not an edge case.
     */
    let created: { user: UserRow; token: string; expiresAt: string };
    try {
      created = db.transaction((): { user: UserRow; token: string; expiresAt: string } => {
        const user = createUser(db, {
          username: body.username,
          passwordHash,
          email: body.email,
        });

        /**
         * `ensureGrant` rather than `grantRole`: on the self-registration path
         * "they already hold it" must be a success, and the `ON CONFLICT DO
         * NOTHING` keeps that as one statement instead of a check and a write
         * with a gap in between. A brand-new account holds nothing, so this
         * always inserts today — the idempotence is here so that a resend or a
         * re-registration flow added later cannot turn into a duplicate-row
         * error.
         */
        ensureGrant(db, {
          subject: user.subject,
          appSlug: target.slug,
          role: baselineRole,
          grantedBy: SELF_REGISTRATION_ACTOR,
        });

        const issued = issueEmailVerification(db, {
          subject: user.subject,
          email: body.email,
        });

        /**
         * Two audit rows for one act, deliberately.
         *
         * `user.register` answers "where did this account come from", with the
         * app and the address it was created against. `grant.create` answers
         * "who granted this and when" — and it has to be its own row because
         * the console finds everything that happened to a grant by filtering on
         * `target_id`, so a grant with no `grant.create` row is invisible to the
         * one query `audit_log` exists to serve.
         *
         * The registrant is the actor on the first (an ordinary account did
         * this, self-service) and **Ward is the actor on the second**: the
         * person did not grant themselves anything, the registration flow did,
         * acting on a flag the operator set. That is the same distinction
         * `granted_by = "self-registration"` records.
         */
        recordAudit(db, {
          actorKind: "account",
          actorSubject: user.subject,
          actorLabel: user.username,
          action: "user.register",
          targetKind: "user",
          targetId: user.subject,
          detail: { app: target.slug, role: baselineRole, ip: address },
        });

        recordAudit(db, {
          actorKind: "system",
          actorLabel: REGISTRATION_ACTOR_LABEL,
          action: "grant.create",
          targetKind: "grant",
          targetId: grantTargetId(user.subject, target.slug, baselineRole),
          detail: {
            subject: user.subject,
            app: target.slug,
            role: baselineRole,
            grantedBy: SELF_REGISTRATION_ACTOR,
          },
        });

        return { user, token: issued.token, expiresAt: issued.row.expires_at };
      })();
    } catch (error) {
      if (isUniqueViolation(error)) {
        return usernameTaken(reply);
      }
      throw error;
    }

    /**
     * The mail goes **after** the commit, and a failure to send does not undo
     * the registration.
     *
     * The alternative — answer `500` when the SMTP host is down — is the worst
     * of the three outcomes available: the account exists and the username is
     * taken, so the person retries, is told the name is unavailable, and
     * concludes somebody beat them to it. Registration succeeded; the side
     * channel did not, and the answer says so in a field brief 09 can render
     * ("we could not send the confirmation — you can still sign in").
     *
     * Nothing here logs the token or the link. In `file` mode the path is
     * logged, which names a file rather than carrying the credential inside it.
     */
    const sent = await deliverVerification({
      request,
      db,
      transport: MAIL,
      publicOrigin: WARD_PUBLIC_ORIGIN,
      user: created.user,
      email: body.email,
      appName: target.name,
      token: created.token,
    });

    request.log.info(
      {
        subject: created.user.subject,
        app: target.slug,
        role: baselineRole,
        verificationSent: sent,
      },
      "account registered",
    );

    return reply.code(201).send({
      subject: created.user.subject,
      username: created.user.username,
      email: created.user.email,
      emailVerified: false,
      app: target.slug,
      role: baselineRole,
      verificationSent: sent,
      verificationExpiresAt: created.expiresAt,
    });
  });

  /**
   * `GET /verify?token=` in its own scope, so the log serializer below applies
   * to it and to nothing else.
   *
   * A nested `register` is the mechanism because Fastify writes the "incoming
   * request" line **before any hook runs** — `lib/route.js` constructs the
   * request, calls `incomingRequest`, and only then starts the `onRequest`
   * chain — so no hook this plugin could add is early enough to scrub the URL.
   * The child logger, however, is built one line earlier and takes the route's
   * serializers with it. Verified empirically, not assumed: `register.test.ts`
   * pipes a real pino stream and asserts the token is absent from the line.
   */
  await app.register(
    async (scope: FastifyInstance): Promise<void> => {
      scope.get(
        "/verify",
        {
          /**
           * **No HEAD route.** Fastify exposes one for every GET by default,
           * running the same handler — and this handler spends a single-use
           * token. A mail scanner or link previewer that issues `HEAD` on the
           * link before the person clicks it would burn the verification and
           * leave them with a dead link, so `HEAD /verify` is simply not a
           * route. (A scanner that issues a real `GET` still burns it; that is
           * an unavoidable cost of a clickable link, and it is survivable here
           * only because verification is not a sign-in gate.)
           */
          exposeHeadRoute: false,
        },
        async (request, reply) => {
          reply.header("cache-control", "no-store");
          /**
           * The URL of this page contains a live token, so nothing may carry it
           * onwards. `no-referrer` stops it leaking through a `Referer` header;
           * the page below has no links or subresources for one to be sent from
           * either, which is belt and braces on purpose.
           */
          reply.header("referrer-policy", "no-referrer");

          const query = verifyQuery.safeParse(request.query);
          if (!query.success) {
            return verifyAnswer(request, reply, 400, "invalid_request");
          }

          const db = await database();
          const outcome = consumeEmailVerification(db, query.data.token);

          if (outcome.status === "expired") {
            request.log.info({ outcome: "expired" }, "verification rejected");
            return verifyAnswer(request, reply, 400, "expired_token");
          }
          if (outcome.status === "invalid") {
            // No subject to name, and nothing audited: this endpoint is fed by
            // anonymous input and a row per bad token is a write amplifier.
            request.log.info({ outcome: "invalid" }, "verification rejected");
            return verifyAnswer(request, reply, 400, "invalid_token");
          }

          request.log.info({ subject: outcome.subject }, "email verified");
          return verifyAnswer(request, reply, 200, "verified");
        },
      );
    },
    { logSerializers: verifyLogSerializers },
  );
}

/**
 * Build, send and account for the verification mail. Never throws.
 *
 * Separated from the handler because it is the one step whose failure is not a
 * failure of the request, and reading that as three lines in the middle of the
 * happy path invites somebody to "simplify" it into an `await` that rejects.
 */
async function deliverVerification(params: {
  request: FastifyRequest;
  db: Database.Database;
  transport: MailTransport;
  publicOrigin: string;
  user: UserRow;
  /**
   * Taken from the validated body rather than read back off `user.email`, which
   * is nullable in the schema — an owner-issued account has no address — and
   * would need a non-null assertion to use here. The address that was submitted
   * is the address the token was minted for; they are the same string.
   */
  email: string;
  appName: string;
  token: string;
}): Promise<boolean> {
  const message = verificationMail({
    to: params.email,
    username: params.user.username,
    appName: params.appName,
    link: verificationLink(params.publicOrigin, params.token),
    expiresInHours: EMAIL_VERIFICATION_TTL_HOURS,
  });

  try {
    const result = await sendMail(message, params.transport);
    params.request.log.info(
      {
        subject: params.user.subject,
        transport: result.kind,
        // The file path is safe to log; the token inside the file is not, and
        // is not here. In `smtp` mode there is no path at all.
        path: result.kind === "file" ? result.path : undefined,
      },
      "verification mail sent",
    );
    return true;
  } catch (error) {
    /**
     * Logged at `error` with the real error, because this is an operator
     * problem — a dead SMTP host, an unwritable outbox — and audited so that it
     * is still discoverable tomorrow when the log has rotated. The audit detail
     * carries no error text: it is append-only and never pruned, and an SMTP
     * failure message is exactly the sort of string that arrives with a
     * hostname and a credential hint in it.
     */
    params.request.log.error(
      { err: error, subject: params.user.subject },
      "verification mail could not be sent; the account exists and is unverified",
    );
    recordAudit(params.db, {
      actorKind: "system",
      actorLabel: REGISTRATION_ACTOR_LABEL,
      action: "user.verification_mail_failed",
      targetKind: "user",
      targetId: params.user.subject,
      detail: { transport: params.transport.kind },
    });
    return false;
  }
}

/**
 * `409 username_taken` — clear, actionable, and the same answer for every
 * reason a name is unavailable.
 *
 * **On the tension between "clear" and "non-enumerating".** A registration form
 * cannot avoid being a "is this name taken" oracle: usernames are unique
 * because the username *is* the canonical identifier
 * ([decisions-accounts.md](../../../corpus/wiki/decisions-accounts.md)), so a
 * duplicate has to be refused, and the refusal itself carries the fact. Being
 * vague about *why* — `invalid_request`, or a generic "try again" — would cost
 * every real person the one thing they need to know, in the single most likely
 * response this endpoint gives, while costing a prober nothing at all: they
 * learn the same bit from the fact that registration failed.
 *
 * So the answer is plain, and what is withheld is everything *else*. This
 * response is byte-identical whether the existing account is disabled,
 * verified, owner-issued, holds a grant in the app being registered at, or is
 * the break-glass username that has no row anywhere — none of which the caller
 * has any business learning. And note the enumeration Ward does **not** offer
 * at all, which is the one that matters: **there is no "email already
 * registered" error.** `users.email` has no uniqueness constraint, two accounts
 * may share an address, and so `/register` never confirms or denies that an
 * address is known to the estate. prm answers `409 EMAIL_TAKEN` today because
 * email is its primary key; Ward's is the username, and giving up that oracle
 * costs nothing here.
 */
function usernameTaken(reply: FastifyReply): FastifyReply {
  return reply.code(409).send({ error: "username_taken" });
}

/** `403` for a closed app and for an app that does not exist alike. */
function registrationClosed(reply: FastifyReply): FastifyReply {
  return reply.code(403).send({ error: "registration_closed" });
}

/**
 * `429` with `Retry-After`.
 *
 * **No artificial delay before it** — holding the connection open is the denial
 * of service the lockout exists to prevent, and Ward is the runtime dependency
 * of all six apps (see `auth/lockout.ts`). `retryAfterSeconds` is repeated in
 * the body so brief 09 can render the wait without reading a header.
 */
function lockedOut(reply: FastifyReply, retryAfterSeconds: number): FastifyReply {
  reply.header("retry-after", String(retryAfterSeconds));
  return reply.code(429).send({ error: "too_many_attempts", retryAfterSeconds });
}

/** The outcomes `GET /verify` can answer with. */
type VerifyOutcome = "verified" | "expired_token" | "invalid_token" | "invalid_request";

/**
 * Answer `GET /verify` as JSON, or as a page when a browser asked for one.
 *
 * This route is the one Ward endpoint a person reaches by clicking rather than
 * a program reaches by calling, and answering `{"error":"invalid_token"}` to
 * somebody's mail client is a half-built feature. So the body is negotiated:
 * `text/html` in the `Accept` header — which every browser sends and no API
 * client does — gets a page, and everything else gets the JSON the rest of Ward
 * speaks. The status code is the same either way.
 *
 * **The page interpolates nothing.** Every string below is a literal chosen by
 * `outcome`, so there is no escaping rule to get wrong and no path by which a
 * query parameter, an address or a username could reach the markup. Keep it
 * that way: the moment this page renders a value, it needs an HTML escaper and
 * a reason to trust its input.
 */
function verifyAnswer(
  request: FastifyRequest,
  reply: FastifyReply,
  status: number,
  outcome: VerifyOutcome,
): FastifyReply {
  if (!prefersHtml(request.headers.accept)) {
    return reply
      .code(status)
      .send(outcome === "verified" ? { verified: true } : { error: outcome });
  }

  reply.type("text/html; charset=utf-8");
  return reply.code(status).send(verifyPage(outcome));
}

function prefersHtml(accept: string | undefined): boolean {
  return typeof accept === "string" && accept.includes("text/html");
}

/** One static document per outcome. See `verifyAnswer` for the no-interpolation rule. */
function verifyPage(outcome: VerifyOutcome): string {
  const { title, message } = {
    verified: {
      title: "Email confirmed",
      message: "Your email address is confirmed. You can close this page and sign in.",
    },
    expired_token: {
      title: "Link expired",
      message:
        "This confirmation link has expired. Sign in and ask for a new one — your account " +
        "still works, the address is just not confirmed yet.",
    },
    invalid_token: {
      title: "Link not valid",
      message:
        "This confirmation link is not valid. It may already have been used, in which case " +
        "there is nothing left to do.",
    },
    invalid_request: {
      title: "Link not valid",
      message: "This confirmation link is incomplete. Check that it was copied in full.",
    },
  }[outcome];

  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<meta name="referrer" content="no-referrer">',
    `<title>${title}</title>`,
    "<style>body{font:16px/1.5 system-ui,sans-serif;margin:4rem auto;max-width:32rem;padding:0 1rem}</style>",
    "</head><body>",
    `<h1>${title}</h1>`,
    `<p>${message}</p>`,
    "</body></html>",
    "",
  ].join("\n");
}

/**
 * The redacting `req` serializer for the `/verify` scope.
 *
 * Fastify's default serializer logs `url`, and on this one route the URL is a
 * credential. This replaces the query string wholesale rather than the `token`
 * parameter specifically, so a parameter added later cannot leak by being
 * forgotten here.
 *
 * The cast is on the **return type only**. Fastify types a log serializer as
 * returning `string`, while pino's serializers may return any value and the
 * built-in `req` serializer it replaces returns an object — so the honest shape
 * cannot be expressed against the declared type. Everything else about the
 * value matches what Fastify would have logged.
 */
const verifyLogSerializers: Record<string, (value: unknown) => string> = {
  req: ((request: FastifyRequest): unknown => ({
    method: request.method,
    url: withoutQuery(request.url),
    host: request.host,
    remoteAddress: request.ip,
    remotePort: request.socket.remotePort,
  })) as unknown as (value: unknown) => string,
};

/** `/verify?token=abc` → `/verify?<redacted>`. */
function withoutQuery(url: string): string {
  const mark = url.indexOf("?");
  return mark === -1 ? url : `${url.slice(0, mark)}?<redacted>`;
}

/**
 * The lockout key for a request. One line, but its own function so that this
 * surface can be read side-by-side with `/login` and `/console/login` and be
 * seen to key identically.
 *
 * **Never `request.ip`.** Ward binds loopback behind Caddy, so the socket peer
 * is `127.0.0.1` for the entire internet and keying on it would give everyone
 * one shared counter — the sixth registration anywhere in the estate would
 * answer `429` to everybody. See `lockoutKeyFor` for why the *last*
 * `X-Forwarded-For` element is the one that cannot be spoofed.
 */
function lockoutKey(request: FastifyRequest): string {
  return lockoutKeyFor(request.socket.remoteAddress, request.headers["x-forwarded-for"], {
    warn: (detail, message) => {
      request.log.warn(detail, message);
    },
  });
}

/**
 * A PRIMARY KEY or UNIQUE collision from better-sqlite3.
 *
 * Matched on `code` rather than on the message, for the reason
 * `routes/admin/support.ts` records: the messages name columns
 * (`UNIQUE constraint failed: users.username_folded`), so a route that branches
 * on that string leaks the schema if it ever echoes it and breaks silently the
 * next time a migration renames anything. Duplicated here rather than imported
 * because `support.ts` belongs to the console admin plugins and this route is
 * not one of them — a two-line predicate is a better dependency than a shared
 * module reaching across brief boundaries.
 */
function isUniqueViolation(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const code: unknown = (error as { code?: unknown }).code;
  return code === "SQLITE_CONSTRAINT_UNIQUE" || code === "SQLITE_CONSTRAINT_PRIMARYKEY";
}
