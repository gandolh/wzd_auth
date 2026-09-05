import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { Field } from "../components/Field.js";
import { Notice } from "../components/Notice.js";
import { Threshold } from "../components/Threshold.js";
import {
  WardApiError,
  changeOwnPassword,
  getAccount,
  logout,
  revokeOtherSessions,
  type AccountResult,
  type WardErrorCode,
} from "../lib/api.js";
import { appName } from "../lib/estate.js";
import { loginRouteFor, loginUrlFor } from "../lib/next.js";
import {
  CAN_CHANGE_OWN_PASSWORD,
  CAN_READ_OWN_EMAIL,
  CAN_REVOKE_OTHER_SESSIONS,
} from "../lib/self-service.js";
import { deadlineIn, useCountdown } from "../lib/use-countdown.js";
import { formatWait } from "../lib/wait.js";
import { readSession, type Session } from "../lib/session.js";

/**
 * `/ward/account` — self-service, and deliberately minimal.
 *
 * Four things live here:
 *
 * | Asked for | Built against |
 * |---|---|
 * | See my own grants | `POST /introspect` |
 * | See my own email and its verification state | `GET /account` |
 * | Change my password | `POST /account/password` |
 * | Sign out my other devices | `POST /account/sessions/revoke-others` |
 *
 * What is deliberately *not* done for the password change is calling
 * `POST /console/accounts/:subject/password` — that route is superuser-only,
 * so it would either answer `401` or require the break-glass credential to be
 * sitting in somebody's browser, and it takes no current password, which is
 * the entire security property a self-service change has.
 *
 * ## Nothing here is about anybody else
 *
 * No account list, no grant editing, no other person's existence acknowledged.
 * That is the console and it is superuser-only. The strongest version of the
 * rule is structural rather than a review note: every source of identity on
 * this page — `/introspect`, `/account`, `/account/password`,
 * `/account/sessions/revoke-others` — answers **for the caller's own cookie**
 * and cannot be pointed at a subject. There is no parameter to tamper with.
 *
 * ## Signing out is not the same as signing out everywhere
 *
 * `POST /logout` revokes the presented token's family and only that family, so
 * other devices keep working — deliberately, so that signing out of a shared
 * laptop does not sign you out of your phone. Which is also why "sign out my
 * other devices" is a genuinely different operation and not this call with a
 * flag on it.
 *
 * ## A `401 unauthorized` from any of these is a sign-out, not an error
 *
 * `/account`, `/account/password` and `/account/sessions/revoke-others` all
 * answer `401 {"error":"unauthorized"}` for a session that has died since the
 * page loaded — a revoked session, an expired one nothing has refreshed yet.
 * Every component below that calls one of them is handed `onSignedOut` and
 * calls it on that code rather than rendering "that didn't work", which is
 * what a page that treated a dead session as a bug would say.
 */

function passwordMessage(code: WardErrorCode): string {
  switch (code) {
    case "invalid_credentials":
      return "That's not your current password.";
    case "password_too_short":
      return "The new password needs at least 8 characters.";
    case "password_too_long":
      return "That new password is too long.";
    case "unreachable":
      return "Ward isn't answering. Try again in a moment.";
    default:
      return "The password wasn't changed. Try again in a moment.";
  }
}

export function Account(): React.JSX.Element {
  const [session, setSession] = useState<Session>({ status: "loading" });

  const load = useCallback(() => {
    void readSession().then(setSession);
  }, []);

  useEffect(load, [load]);

  /**
   * Drop straight to the signed-out screen, with no round trip.
   *
   * Handed to every component below that calls `/account`,
   * `/account/password` or `/account/sessions/revoke-others`, for a `401
   * unauthorized` on any of them: the session already died, so re-asking
   * `readSession` would only spend a request to learn what the failing call
   * already said.
   */
  const signOut = useCallback(() => {
    setSession({ status: "signed-out" });
  }, []);

  if (session.status === "loading") {
    return (
      <Threshold wide>
        <h1>Your account</h1>
        <p className="ward-lede">Loading.</p>
      </Threshold>
    );
  }

  if (session.status === "unreachable") {
    return (
      <Threshold wide>
        <h1>Ward isn't answering</h1>
        <p className="ward-lede">
          Your session is probably fine — Ward just didn't respond. Try again.
        </p>
        <div className="ward-actions">
          <button className="ward-button" type="button" onClick={load}>
            Try again
          </button>
        </div>
      </Threshold>
    );
  }

  if (session.status === "signed-out") {
    /**
     * Rendered rather than redirected.
     *
     * An automatic bounce to the login form is the same pixels as a session
     * that silently expired while somebody was reading, and it loses the one
     * fact worth knowing: nothing went wrong, the session simply ended. The
     * link carries `?next=/ward/account`, so signing in comes back here.
     */
    return (
      <Threshold wide>
        <h1>You're signed out</h1>
        <p className="ward-lede">
          Sessions end after a while, and this one has. Sign in to see your account.
        </p>
        <p className="ward-prose">
          <Link className="ward-link" to={loginRouteFor("/ward/account")}>
            Sign in
          </Link>
        </p>
      </Threshold>
    );
  }

  return <SignedIn session={session} onSignedOut={signOut} />;
}

/**
 * The caller's own record, loaded once per sign-in.
 *
 * `"off"` when `CAN_READ_OWN_EMAIL` is false, so a caller can render exactly
 * as if the flag did not exist rather than branching on both a flag and a
 * load state. A `401 unauthorized` here calls `onSignedOut` rather than
 * setting `"failed"` — see the module docblock.
 */
type OwnAccount =
  | { state: "off" }
  | { state: "loading" }
  | { state: "ready"; data: AccountResult }
  | { state: "failed" };

function useOwnAccount(onSignedOut: () => void): OwnAccount {
  const [state, setState] = useState<OwnAccount>(
    CAN_READ_OWN_EMAIL ? { state: "loading" } : { state: "off" },
  );

  useEffect(() => {
    if (!CAN_READ_OWN_EMAIL) return;
    let live = true;
    void getAccount().then(
      (data) => {
        if (live) setState({ state: "ready", data });
      },
      (error: unknown) => {
        if (!live) return;
        if (error instanceof WardApiError && error.code === "unauthorized") {
          onSignedOut();
          return;
        }
        setState({ state: "failed" });
      },
    );
    return () => {
      live = false;
    };
  }, [onSignedOut]);

  return state;
}

function SignedIn({
  session,
  onSignedOut,
}: {
  session: Extract<Session, { status: "signed-in" }>;
  onSignedOut: () => void;
}): React.JSX.Element {
  const grants = Object.entries(session.grants);
  const account = useOwnAccount(onSignedOut);

  /**
   * The unverified-address prompt.
   *
   * Only rendered once `GET /account` has actually answered, and only when
   * there is an address to confirm at all — an owner-issued account's `email`
   * is `null`, and there is nothing to nag about there. Sourced from the
   * account's own record rather than from what `/login` said earlier in the
   * page's lifetime, so it is still correct after a reload.
   */
  const unverified =
    account.state === "ready" && account.data.email !== null && !account.data.emailVerified;

  return (
    <Threshold
      wide
      footer={<>Signed in as {session.username}. Ward keeps the estate's accounts.</>}
    >
      <h1>Your account</h1>
      <p className="ward-lede">
        One account for every app here. What you can reach in each of them is set per app, below.
      </p>

      {unverified && (
        <Notice tone="info">
          Your email address isn't confirmed. Nothing is blocked by that — confirming an address
          doesn't unlock anything in Ward — but the confirmation link only lasts 24 hours and Ward
          can't send a new one.
        </Notice>
      )}

      <h2>Who you are</h2>
      <dl className="ward-facts">
        <dt>Username</dt>
        <dd>{session.username}</dd>
        <dt>Account id</dt>
        {/*
          The subject. Shown because it is the id every app in the estate keys
          your data on, so it is the one string worth quoting when something has
          gone wrong somewhere else. Monospace because it is meant to be read
          character by character.
        */}
        <dd className="ward-mono">{session.subject}</dd>
        {account.state === "ready" && (
          <>
            <dt>Email</dt>
            <dd>
              {account.data.email === null
                ? "None on record — this account was created from the console."
                : `${account.data.email} ${account.data.emailVerified ? "(confirmed)" : "(unconfirmed)"}`}
            </dd>
          </>
        )}
      </dl>

      <h2>What you can reach</h2>
      {grants.length === 0 ? (
        <p className="ward-prose">
          No app access yet. Access is granted per app by whoever runs the estate — ask them, and it
          will appear here.
        </p>
      ) : (
        <>
          <p className="ward-prose">
            Read-only. Changing any of this is done by whoever runs the estate.
          </p>
          <ul className="ward-grants">
            {grants.map(([slug, roles]) => (
              <li key={slug}>
                <span className="ward-grants__app">{appName(slug)}</span>
                <span className="ward-grants__roles">
                  {roles.length === 0 ? "no roles" : roles.join(", ")}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}

      <ChangePassword onSignedOut={onSignedOut} />
      <OtherDevices onSignedOut={onSignedOut} />
      <SignOut username={session.username} />
    </Threshold>
  );
}

/**
 * Change password.
 *
 * Three fields, the right `autoComplete` values, the current password
 * required, errors bound with `aria-describedby`, behind
 * `CAN_CHANGE_OWN_PASSWORD`.
 *
 * The current password is required by the form and by the route. It is not
 * ceremony: without it, an XSS anywhere on the estate's single origin — or a
 * borrowed unlocked laptop — becomes a permanent account takeover, and there
 * is no recovery channel behind an owner-issued account to take it back with.
 *
 * `POST /account/password` runs on **its own lockout budget**, separate from
 * `/login`'s, so a `429` here is answered with its own countdown rather than
 * `passwordMessage`'s generic line — and the copy says plainly that signing in
 * still works, because a person reading "too many attempts" right after
 * typing a password has every reason to assume the worst.
 */
function ChangePassword({ onSignedOut }: { onSignedOut: () => void }): React.JSX.Element {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<WardErrorCode | undefined>();
  const [mismatch, setMismatch] = useState(false);
  const [done, setDone] = useState(false);
  const [lockedUntil, setLockedUntil] = useState<number | undefined>();

  const waitLeft = useCountdown(lockedUntil);
  const lockedOut = lockedUntil !== undefined && waitLeft > 0;

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (busy || lockedOut) return;

    // Checked here because the API cannot: it receives one new password and has
    // no way to know somebody mistyped it twice the same way. This is the only
    // client-side rule on this form.
    if (next !== confirm) {
      setMismatch(true);
      setFailure(undefined);
      return;
    }
    setMismatch(false);
    setBusy(true);
    setFailure(undefined);
    try {
      await changeOwnPassword(current, next);
      setDone(true);
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (error) {
      const code = error instanceof WardApiError ? error.code : "unexpected";
      if (code === "unauthorized") {
        onSignedOut();
        return;
      }
      if (code === "too_many_attempts") {
        const seconds = error instanceof WardApiError ? (error.retryAfterSeconds ?? 60) : 60;
        setLockedUntil(deadlineIn(seconds));
      }
      setFailure(code);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h2>Password</h2>
      {!CAN_CHANGE_OWN_PASSWORD ? (
        <div className="ward-unavailable">
          <p>
            You can't change your own password here yet — Ward has no endpoint for it. Ask whoever
            runs the estate to set a new one from the console.
          </p>
        </div>
      ) : (
        <>
          {done && (
            <Notice tone="info" live="assertive">
              Password changed. This browser is still signed in — Ward gave it a fresh session just
              now. The one it had a moment ago, and every other device signed in as you, has been
              ended.
            </Notice>
          )}
          {lockedOut && (
            <Notice tone="wait">
              Too many attempts at changing your password. This is a separate limit from signing in
              — it doesn't affect that. Try again in <strong>{formatWait(waitLeft)}</strong>.
            </Notice>
          )}
          {failure !== undefined && failure !== "too_many_attempts" && (
            <Notice tone="error">{passwordMessage(failure)}</Notice>
          )}
          <form
            className="ward-form"
            noValidate
            onSubmit={(event) => {
              void onSubmit(event);
            }}
          >
            <Field
              id="ward-current-password"
              label="Current password"
              name="current-password"
              type="password"
              autoComplete="current-password"
              required
              value={current}
              disabled={busy || lockedOut}
              onChange={(event) => {
                setCurrent(event.target.value);
              }}
            />
            <Field
              id="ward-new-password"
              label="New password"
              name="new-password"
              type="password"
              autoComplete="new-password"
              required
              minLength={8}
              hint="At least 8 characters."
              value={next}
              disabled={busy || lockedOut}
              onChange={(event) => {
                setNext(event.target.value);
              }}
            />
            <Field
              id="ward-confirm-password"
              label="New password again"
              name="confirm-password"
              type="password"
              autoComplete="new-password"
              required
              value={confirm}
              error={mismatch ? "The two new passwords don't match." : undefined}
              disabled={busy || lockedOut}
              onChange={(event) => {
                setConfirm(event.target.value);
              }}
            />
            <div className="ward-actions">
              <button className="ward-button" type="submit" disabled={busy || lockedOut}>
                {busy ? "Changing…" : "Change password"}
              </button>
              <span className="ward-field__hint">
                Signs out every other device that was signed in as you. This one stays signed in —
                it gets a fresh session automatically.
              </span>
            </div>
          </form>
        </>
      )}
    </>
  );
}

/**
 * Sign out my other devices.
 *
 * This is the item on the self-service page that earns its place on a specific
 * argument, and the argument is worth repeating where the control is: an
 * owner-issued account has no verified email and therefore **no recovery
 * channel**, so this is the only self-serve move available to somebody who
 * thinks their session has been stolen.
 */
function OtherDevices({ onSignedOut }: { onSignedOut: () => void }): React.JSX.Element {
  const [busy, setBusy] = useState(false);
  const [revoked, setRevoked] = useState<number | undefined>();
  const [failure, setFailure] = useState<WardErrorCode | undefined>();

  async function onClick(): Promise<void> {
    if (busy) return;
    setBusy(true);
    setFailure(undefined);
    try {
      setRevoked((await revokeOtherSessions()).revoked);
    } catch (error) {
      const code = error instanceof WardApiError ? error.code : "unexpected";
      if (code === "unauthorized") {
        onSignedOut();
        return;
      }
      setFailure(code);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h2>Other devices</h2>
      {!CAN_REVOKE_OTHER_SESSIONS ? (
        <div className="ward-unavailable">
          <p>
            Signing out your other devices isn't possible yet — Ward has no endpoint for it. If you
            think somebody else is signed in as you, ask whoever runs the estate to revoke your
            sessions from the console, and change your password while you're there.
          </p>
        </div>
      ) : (
        <>
          <p className="ward-prose">
            Ends every other signed-in session and leaves this one alone. Worth doing if you think
            somebody else has your session.
          </p>
          {revoked !== undefined && (
            <Notice tone="info" live="assertive">
              {revoked === 0
                ? "No other sessions were signed in."
                : `${String(revoked)} other ${revoked === 1 ? "session" : "sessions"} signed out.`}
            </Notice>
          )}
          {failure !== undefined && (
            <Notice tone="error">
              That didn&apos;t work. Try again, and if it keeps failing ask whoever runs the estate
              to revoke your sessions.
            </Notice>
          )}
          <div className="ward-actions">
            <button
              className="ward-button ward-button--danger"
              type="button"
              disabled={busy}
              onClick={() => {
                void onClick();
              }}
            >
              {busy ? "Signing out…" : "Sign out my other devices"}
            </button>
          </div>
        </>
      )}
    </>
  );
}

/**
 * Sign out of this device. The one destructive thing on this page that works.
 *
 * `/logout` always answers `204`, so there is no failure branch to render —
 * only a network failure, and the honest response to that is to send the person
 * to the login page anyway, because the local cookies are the only thing that
 * mattered and Ward will refuse them on the next call regardless.
 *
 * A **full navigation**, not a router push: signing out has to leave the SPA so
 * that nothing in memory outlives the session. `location.replace` rather than
 * `assign`, so Back does not land on a signed-out account page.
 */
function SignOut({ username }: { username: string }): React.JSX.Element {
  const [busy, setBusy] = useState(false);

  async function onClick(): Promise<void> {
    setBusy(true);
    try {
      await logout();
    } catch {
      // Nothing to do about it, and nothing to tell the person: the cookies are
      // either cleared or about to be refused.
    }
    window.location.replace(loginUrlFor("/"));
  }

  return (
    <>
      <h2>Sign out</h2>
      <p className="ward-prose">Ends this session only, on this device. Signed in as {username}.</p>
      <div className="ward-actions">
        <button
          className="ward-button ward-button--quiet"
          type="button"
          disabled={busy}
          onClick={() => {
            void onClick();
          }}
        >
          {busy ? "Signing out…" : "Sign out"}
        </button>
      </div>
    </>
  );
}
