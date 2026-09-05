/**
 * The console's own sign-in screen.
 *
 * ## It is deliberately not the ordinary login page
 *
 * The brief asks for this and calls it a safety property rather than a
 * preference, and the reasoning is worth keeping next to the code: there is
 * exactly one console credential, it lives in Ward's environment, it cannot be
 * revoked or rotated without a redeploy, and every route behind this form
 * changes who can reach what. Someone reaching for break-glass should be able
 * to see that they have before they type.
 *
 * So this screen shares no shape with `pages/Login.tsx`: a dark surface from
 * the console tokens, a hazard band, a two-column layout instead of a narrow
 * centred card, and the standing terms of the credential written out beside the
 * form rather than hidden in a footer. The words are the design here — they are
 * the only place an operator learns that using this thing leaves a permanent
 * trace and that rotating it is a deploy.
 *
 * ## What it does not do
 *
 * It does not offer a password reset, because there is no path to one: rotating
 * `WARD_ADMIN_PASSWORD` is an `.env` edit and a restart, by decision. It offers
 * no "remember me": the server's sliding idle window is the only deadline and a
 * second clock in the browser would drift from it. And it never renders a
 * password back — the field is cleared the moment the request is sent, so a
 * failed attempt does not leave a credential sitting in the DOM.
 */

import { useRef, useState } from "react";

import { consoleApi, ConsoleApiError, type ConsoleSessionView } from "../../console-api.js";
import { Alert, TextField } from "./ui.js";
import { formatRemaining } from "./format.js";

export function ConsoleLogin({
  onSignedIn,
  notice,
}: {
  onSignedIn: (session: ConsoleSessionView) => void;
  /** Why the operator is looking at this screen, when they were just inside. */
  notice?: string;
}): React.JSX.Element {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>(undefined);
  const usernameRef = useRef<HTMLInputElement>(null);

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    if (busy) return;

    setBusy(true);
    setFailure(undefined);
    try {
      const session = await consoleApi.login({ username, password });
      // Cleared on the way out, whatever happens next.
      setPassword("");
      onSignedIn(session);
    } catch (error) {
      /**
       * The password goes first, before anything is rendered. A refused attempt
       * is very often a mistyped password, and leaving it in the field means
       * leaving a near-miss of the estate's break-glass credential in the DOM
       * for however long the operator stares at the error.
       */
      setPassword("");
      if (error instanceof ConsoleApiError) {
        setFailure(
          error.status === 429 && error.retryAfterSeconds !== undefined
            ? `${error.message} Try again in ${formatRemaining(error.retryAfterSeconds)}.`
            : error.message,
        );
      } else {
        setFailure("The sign-in request failed before it reached Ward.");
      }
      usernameRef.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  return (
    // The attribute is set here as well as on brief 09's wrapper. It is what
    // re-points the token palette, and this screen must be unmistakable even if
    // it is ever rendered outside that wrapper.
    <div className="wc-gate" data-ward-surface="console">
      <div className="wc-hazard" />
      <div className="wc-gate-inner">
        <div>
          <h1>Ward console</h1>
          <p className="wc-lede">
            Break-glass access to the estate&rsquo;s identity service. Sign in with the credential
            from Ward&rsquo;s environment, not with a Ward account.
          </p>

          {notice === undefined || failure !== undefined ? null : (
            <Alert tone="notice" title="Signed out">
              {notice}
            </Alert>
          )}

          {failure === undefined ? null : (
            <Alert tone="error" title="Refused" takeFocus>
              {failure}
            </Alert>
          )}

          <form
            className="wc-form"
            onSubmit={(event) => {
              void submit(event);
            }}
          >
            <TextField
              label="Console username"
              name="username"
              value={username}
              onChange={setUsername}
              autoComplete="username"
              required
              disabled={busy}
              opaque
              spellCheck={false}
              inputRef={usernameRef}
              hint="WARD_ADMIN_USERNAME, as set in Ward's environment."
            />
            <TextField
              label="Console password"
              name="password"
              type="password"
              value={password}
              onChange={setPassword}
              autoComplete="current-password"
              required
              disabled={busy}
            />
            <div className="wc-actions">
              <button type="submit" className="wc-btn" data-tone="primary" disabled={busy}>
                {busy ? "Signing in…" : "Sign in to the console"}
              </button>
            </div>
          </form>
        </div>

        <div>
          <h2 className="wc-wordmark">What this credential is</h2>
          <dl className="wc-gate-terms">
            <dt>It is not an account</dt>
            <dd>
              Ward&rsquo;s database holds no row for it: no subject, no grants, nothing in the
              account list below, and nothing to revoke. It reaches this console and no app in the
              estate, because access in this estate is a grant and this credential holds none.
            </dd>

            <dt>It cannot be rotated from here</dt>
            <dd>
              Changing the password means editing <span className="wc-id">WARD_ADMIN_PASSWORD</span>{" "}
              and restarting Ward. That friction is deliberate for a credential of this kind, and a
              restart also ends every open console session.
            </dd>

            <dt>Every attempt is recorded</dt>
            <dd>
              Successes and failures both land in the audit log. Since the credential cannot be
              revoked, that log is the only observability it has — which is why this console renders
              it.
            </dd>

            <dt>Day-to-day work belongs elsewhere</dt>
            <dd>
              The apps are run by an ordinary Ward account holding explicit admin grants, created on
              the accounts screen. This credential is for when something is broken.
            </dd>
          </dl>
        </div>
      </div>
    </div>
  );
}
