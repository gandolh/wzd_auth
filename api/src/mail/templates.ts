import type { OutgoingMail } from "./transport.js";

/**
 * The messages Ward sends. Today there is exactly one.
 *
 * ## Plain text, no HTML part
 *
 * A verification mail carries one sentence and one link. An HTML alternative
 * would add a second body to keep in step with the first, an escaping rule for
 * every value interpolated into it, and a reason for a spam filter to look
 * harder — in exchange for a coloured button. `text/plain` also means the link
 * is visible as the URL it is, which is the opposite of the phishing shape
 * ("click here" over a hidden href) and is worth something on a mail that asks
 * somebody to click a link.
 *
 * ## Templates are pure
 *
 * Nothing here reads the environment, the database or the clock. The public
 * origin and the token arrive as arguments, so a test can assert the exact
 * bytes of a message without any of that being set up — and the module cannot
 * grow a dependency on `config.ts` that would make importing it validate the
 * environment.
 */

/**
 * The path prefix Caddy strips.
 *
 * Ward is served with `handle_path /ward-api/*`, so the Fastify route
 * `GET /verify` is `GET /ward-api/verify` to a browser. **This is the
 * browser-visible half**, and getting it backwards is the same class of mistake
 * as the refresh cookie's `Path` (see `auth/cookie.ts`): a link to
 * `https://gandolh.ro/verify` 404s in production while every test passes,
 * because `app.inject()` never sees the prefix at all.
 */
export const WARD_API_PREFIX = "/ward-api";

/**
 * Where a **person** lands when they click the link in their inbox: brief 09's
 * `/ward/verify` screen, served by the UI bundle.
 *
 * This used to be `${WARD_API_PREFIX}/verify`, the API's own server-rendered
 * page, which meant the one screen built for this moment was not on the path
 * anybody actually takes. Both pages work — the API route stays, because it is
 * what a non-browser client uses and it is content-negotiated for exactly that
 * — but the mail goes to the UI, which can say "your account works, the address
 * just isn't confirmed" and offer somewhere to go next.
 *
 * Note that the UI page then calls `GET /ward-api/verify` itself to spend the
 * token, so the API route is still what performs the verification. Only the
 * first hop moved.
 */
export const WARD_UI_VERIFY_PATH = "/ward/verify";

/**
 * The clickable verification URL.
 *
 * `publicOrigin` must be a bare origin — `config.ts` validates
 * `WARD_PUBLIC_ORIGIN` as exactly that and strips any trailing slash, so this
 * concatenation cannot produce a double slash or inherit a path somebody put in
 * the variable.
 *
 * The token is percent-encoded even though `generateVerificationToken()`
 * returns hex and has nothing to encode. It costs nothing, and it means a later
 * change to the token alphabet — base64url, say, whose `=` padding is not
 * query-safe — cannot silently produce links that truncate at the first
 * special character.
 */
export function verificationLink(publicOrigin: string, token: string): string {
  return `${publicOrigin}${WARD_UI_VERIFY_PATH}?token=${encodeURIComponent(token)}`;
}

export interface VerificationMailParams {
  /** The address being proved. Not necessarily `users.email` yet. */
  to: string;
  /** As the person typed it, for the greeting. Nothing keys on it. */
  username: string;
  /** `apps.name` — the app they signed up at, not "Ward". See below. */
  appName: string;
  /** From `verificationLink`. */
  link: string;
  /** How long the link lives, for the sentence that says so. */
  expiresInHours: number;
}

/**
 * The mail sent by `POST /register`.
 *
 * **It names the app, not Ward.** Registration happens *at an app* and confers
 * that app's baseline role
 * ([decisions-accounts.md](../../../corpus/wiki/decisions-accounts.md)); a
 * stranger who signed up at `public-resource-map` has never heard of Ward and a
 * message from an unrecognised service asking them to click a link is
 * indistinguishable from phishing. The footer says where it came from, because
 * the address it arrives from is `gandolh.ro`'s and that should not be a
 * surprise either.
 *
 * The "if this was not you" paragraph is not boilerplate: usernames are chosen
 * by the registrant and the address is unverified, so anybody can send this
 * mail to anybody once. What makes that harmless is the line after it — an
 * unverified address confers nothing, and ignoring the mail is a complete
 * response.
 */
export function verificationMail(params: VerificationMailParams): OutgoingMail {
  const hours = params.expiresInHours;
  const plural = hours === 1 ? "hour" : "hours";

  return {
    to: params.to,
    subject: `Confirm your email address for ${params.appName}`,
    text: [
      `Hello ${params.username},`,
      ``,
      `An account was created for ${params.appName} using this email address.`,
      `Open this link to confirm the address is yours:`,
      ``,
      `  ${params.link}`,
      ``,
      `The link works once and stops working after ${hours} ${plural}.`,
      ``,
      `If you did not create this account you can ignore this message. An`,
      `unconfirmed address is not used for anything, and nobody can sign in as`,
      `you without your password.`,
      ``,
      `— sent by Ward, the sign-in service for gandolh.ro`,
      ``,
    ].join("\n"),
  };
}
