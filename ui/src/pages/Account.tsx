import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { Field } from "../components/Field.js";
import { Notice } from "../components/Notice.js";
import { Threshold } from "../components/Threshold.js";
import {
  WardApiError,
  changeOwnPassword,
  logout,
  revokeOtherSessions,
  type WardErrorCode,
} from "../lib/api.js";
import { appName } from "../lib/estate.js";
import { loginRouteFor, loginUrlFor } from "../lib/next.js";
import { CAN_CHANGE_OWN_PASSWORD, CAN_REVOKE_OTHER_SESSIONS } from "../lib/self-service.js";
import { forgetLogin, readSession, recallLogin, type Session } from "../lib/session.js";

/**
 * `/ward/account` — self-service, and deliberately minimal.
 *
 * Three things belong here by decision, and it is worth being blunt about the
 * state of each, because two of them cannot be built against today's API:
 *
 * | Asked for | State |
 * |---|---|
 * | See my own grants | **built** — `POST /introspect` reads them back |
 * | Change my password | **no endpoint** — see `lib/self-service.ts` |
 * | Sign out my other devices | **no endpoint** — see `lib/self-service.ts` |
 *
 * The two gaps are rendered as gaps: the heading is there, the sentence says
 * what is missing and what to do instead, and the form appears the moment its
 * flag in `lib/self-service.ts` flips. What is deliberately *not* done is
 * calling `POST /console/accounts/:subject/password` to fake the first one —
 * that route is superuser-only, so it would either answer `401` or require the
 * break-glass credential to be sitting in somebody's browser, and it takes no
 * current password, which is the entire security property a self-service change
 * has.
 *
 * ## Nothing here is about anybody else
 *
 * No account list, no grant editing, no other person's existence acknowledged.
 * That is the console and it is superuser-only. The strongest version of the
 * rule is structural rather than a review note: this page's only source of
 * identity is `/introspect`, which answers **for the caller's own cookie** and
 * cannot be pointed at a subject. There is no parameter to tamper with.
 *
 * ## Signing out is not the same as signing out everywhere
 *
 * `POST /logout` revokes the presented token's family and only that family, so
 * other devices keep working — deliberately, so that signing out of a shared
 * laptop does not sign you out of your phone. Which is also why "sign out my
 * other devices" is a genuinely different operation and not this call with a
 * flag on it.
 */

function passwordMessage(code: WardErrorCode): string {
  switch (code) {
    case "invalid_credentials":
      return "That's not your current password.";
    case "password_too_short":
      return "The new password needs at least 8 characters.";
    case "password_too_long":
      return "That new password is too long.";
    case "too_many_attempts":
      return "Too many attempts. Wait a few minutes and try again.";
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

  return <SignedIn session={session} />;
}

function SignedIn({
  session,
}: {
  session: Extract<Session, { status: "signed-in" }>;
}): React.JSX.Element {
  const grants = Object.entries(session.grants);

  /**
   * The unverified-address prompt, and the one place it appears.
   *
   * Read from what `POST /login` said earlier **in this page's lifetime**,
   * because `/introspect` returns exactly four fields and none of them is
   * `emailVerified` — see `lib/self-service.ts`. After a reload the prompt is
   * absent rather than wrong, which is the right direction to be incomplete in:
   * a stale "your address is unconfirmed" shown to somebody who confirmed it
   * ten minutes ago is worse than no prompt at all.
   *
   * Also checked against this session's subject, so a login as one person
   * followed by a sign-in as another in the same tab cannot show the first
   * person's state.
   */
  const hint = recallLogin();
  const unverified = hint !== undefined && hint.subject === session.subject && !hint.emailVerified;

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

      <ChangePassword />
      <OtherDevices />
      <SignOut username={session.username} />
    </Threshold>
  );
}

/**
 * Change password.
 *
 * The form is complete and correct — three fields, the right `autoComplete`
 * values, the current password required, errors bound with `aria-describedby`
 * — and it is behind `CAN_CHANGE_OWN_PASSWORD` because
 * `POST /ward-api/account/password` does not exist. That flag is the whole
 * wiring job when it lands.
 *
 * The current password is required by the form and would be required by the
 * route. It is not ceremony: without it, an XSS anywhere on the estate's single
 * origin — or a borrowed unlocked laptop — becomes a permanent account
 * takeover, and there is no recovery channel behind an owner-issued account to
 * take it back with.
 */
function ChangePassword(): React.JSX.Element {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<WardErrorCode | undefined>();
  const [mismatch, setMismatch] = useState(false);
  const [done, setDone] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (busy) return;

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
      setFailure(error instanceof WardApiError ? error.code : "unexpected");
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
              Password changed. Any other device signed in as you has been signed out.
            </Notice>
          )}
          {failure !== undefined && <Notice tone="error">{passwordMessage(failure)}</Notice>}
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
              disabled={busy}
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
              disabled={busy}
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
              disabled={busy}
              onChange={(event) => {
                setConfirm(event.target.value);
              }}
            />
            <div className="ward-actions">
              <button className="ward-button" type="submit" disabled={busy}>
                {busy ? "Changing…" : "Change password"}
              </button>
              <span className="ward-field__hint">
                Changing your password signs out every other device.
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
 * thinks their session has been stolen. It needs
 * `POST /ward-api/account/sessions/revoke-others`, which does not exist —
 * making this the most consequential gap in brief 09.
 */
function OtherDevices(): React.JSX.Element {
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
      setFailure(error instanceof WardApiError ? error.code : "unexpected");
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
    forgetLogin();
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
