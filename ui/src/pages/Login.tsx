import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { Field } from "../components/Field.js";
import { Notice } from "../components/Notice.js";
import { Threshold } from "../components/Threshold.js";
import { WardApiError, login, type WardErrorCode } from "../lib/api.js";
import { rootName } from "../lib/estate.js";
import { resolveNext } from "../lib/next.js";
import { rememberLogin } from "../lib/session.js";
import { deadlineIn, useCountdown } from "../lib/use-countdown.js";
import { formatWait } from "../lib/wait.js";

/**
 * `/ward/login` — the estate's one sign-in form.
 *
 * Every person who uses any app in the estate sees this page, and they see it
 * on their way to somewhere else. Three calls follow from that:
 *
 * 1. **The destination is the headline.** `?next=` says where somebody was
 *    going, so the page leads with "Continue to Atrium" and puts Ward's own
 *    name in the corner at the smallest size on the screen. The recorded cost
 *    of one central login page is that two strongly-designed apps hand their
 *    sign-in moment to a third identity; naming the destination is the one
 *    thing this page can do to make the interruption read as short.
 * 2. **Nothing is between the person and the form.** No illustration, no
 *    marketing line, no motion on load. The first Tab from a cold page lands in
 *    the username field.
 * 3. **The error states are the feature.** Brief 09 exists because six apps
 *    each got these wrong differently. There are exactly four things the API
 *    can say, and this page says each of them once, correctly.
 *
 * ## What the API says, and what this renders
 *
 * | API | Rendered as |
 * |---|---|
 * | `401 invalid_credentials` | "check your username and password" — **never** which half |
 * | `403 account_disabled` | said plainly; it only arrives after the password verified |
 * | `429 too_many_attempts` | a **wait**, counting down, with submit disabled |
 * | `400 invalid_request` | prevented client-side; rendered as a bug if it happens |
 *
 * The first row is the one worth guarding. `/login` spends a dummy hash on an
 * unknown username so the two branches cost the same, and returns a
 * byte-identical body — an account-enumeration oracle closed at real expense in
 * the API. A UI that rendered "no such user" would reopen it from the outside
 * with no way for the API to stop it.
 *
 * ## The unverified-email prompt is deliberately not here
 *
 * `POST /login` returns `emailVerified`, and it is tempting to interrupt with a
 * "please confirm your address" step. That would be wrong twice over:
 * `email_verified` gates nothing in Ward — it blocks no sign-in and no grant —
 * and there is no resend endpoint, so the interruption would carry no action.
 * Worse, it would put a stop sign in the middle of a handover this whole page
 * is designed to keep short. The prompt lives on `/ward/account`, which is
 * where somebody has actually come to look at their account, and the login
 * result is remembered in memory so that page can show it.
 */

/** The one message per failure. Sentences live in the UI; codes on the wire. */
function messageFor(code: WardErrorCode): string {
  switch (code) {
    case "invalid_credentials":
      // Never "no such user", never "wrong password". One sentence for both,
      // because the API deliberately gives one answer for both.
      return "That username and password don't match. Check both and try again.";
    case "account_disabled":
      // Safe to say plainly: this only arrives after the password verified, so
      // the person reading it is the account holder.
      return "This account is turned off. Ask whoever runs the estate to turn it back on.";
    case "unreachable":
      return "Ward isn't answering. Check your connection and try again.";
    case "invalid_request":
      // The form does not let this happen, so if it arrives something upstream
      // changed shape. Say so rather than blaming the person's typing.
      return "Ward refused the sign-in request. Reload the page and try again.";
    default:
      return "Sign-in didn't work. Try again in a moment.";
  }
}

export function Login(): React.JSX.Element {
  const [params] = useSearchParams();

  /**
   * Resolved once per `?next=` value, not per render and not per keystroke.
   *
   * The decision drives the heading, so it is read before anything is typed
   * and cannot change while somebody is typing. A refused value silently
   * becomes `/` — the person who followed a bad link needs to sign in, not to
   * read a diagnostic about the link.
   */
  const destination = useMemo(() => resolveNext(params.get("next")), [params]);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [failure, setFailure] = useState<WardErrorCode | undefined>();
  const [missing, setMissing] = useState<{ username: boolean; password: boolean }>({
    username: false,
    password: false,
  });
  const [lockedUntil, setLockedUntil] = useState<number | undefined>();

  const waitLeft = useCountdown(lockedUntil);
  const lockedOut = lockedUntil !== undefined && waitLeft > 0;
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  /**
   * Focus the first field on arrival.
   *
   * The only autofocus in this UI, and it earns its place: this page has one
   * job, everybody who lands on it is here to do that job, and a password
   * manager fills a focused field without a click. It is not applied to the
   * register or account pages, where there is something to read first.
   */
  useEffect(() => {
    usernameRef.current?.focus();
  }, []);

  const heading =
    destination.accepted && destination.root !== ""
      ? `Continue to ${rootName(destination.root)}`
      : "Sign in";

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (submitting || lockedOut) return;

    // Client-side only for the two things the person can see and fix. Anything
    // about the password's *content* is the API's to judge — a length rule
    // enforced in two places disagrees with itself eventually, and on the login
    // path a rejected-length password simply cannot match a stored hash anyway.
    const blank = { username: username.trim() === "", password: password === "" };
    setMissing(blank);
    if (blank.username || blank.password) {
      setFailure(undefined);
      /**
       * Focus the first field that is empty.
       *
       * Without this, focus stays on the submit button and a keyboard or screen
       * reader user is told, three elements away, that something they cannot
       * see is wrong. The API failures move focus to the notice for the same
       * reason (see `Notice`); a field-level failure has a better target than a
       * notice, which is the field.
       */
      (blank.username ? usernameRef : passwordRef).current?.focus();
      return;
    }

    setSubmitting(true);
    setFailure(undefined);
    try {
      const result = await login(username.trim(), password);
      rememberLogin(result);

      /**
       * A full navigation, not a router push.
       *
       * `destination.path` is a path on this origin that is usually **outside
       * this SPA** — `/atrium/`, `/prm/map` — so React Router would render a
       * 404 inside Ward rather than leaving it. `assign` also leaves the login
       * page in history, which is right: Back from the app returns here, and
       * the cookie is already set, so nothing is retyped.
       *
       * No state is cleared first and the submitting flag stays on: the page is
       * about to be replaced, and re-enabling a form for the few milliseconds
       * before that happens is an invitation to double-submit.
       */
      window.location.assign(destination.path);
    } catch (error) {
      const code = error instanceof WardApiError ? error.code : "unexpected";
      if (code === "too_many_attempts") {
        const seconds = error instanceof WardApiError ? (error.retryAfterSeconds ?? 60) : 60;
        setLockedUntil(deadlineIn(seconds));
      }
      setFailure(code);
      setSubmitting(false);
    }
  }

  return (
    <Threshold
      footer={
        <>
          One sign-in for every app here.{" "}
          <Link className="ward-link" to="/account">
            Your account
          </Link>
        </>
      }
    >
      <h1>{heading}</h1>
      <p className="ward-lede">
        {destination.accepted && destination.root !== ""
          ? "Ward keeps the estate's accounts. Sign in once and you're through."
          : "Ward keeps the estate's accounts. One sign-in covers every app here."}
      </p>

      {/*
        The lockout comes first and is a `wait`, not an `error`. It is the only
        failure on this page with a concrete next step, and the step is
        "nothing, for this long" — so it reads as a clock, the number counts
        down, and the button below is disabled until it runs out. A person who
        sees "sign-in failed" tries again and extends their own lockout.
      */}
      {lockedOut && (
        <Notice tone="wait">
          Too many sign-in attempts from your network. Try again in{" "}
          <strong>{formatWait(waitLeft)}</strong>.
        </Notice>
      )}

      {failure !== undefined && failure !== "too_many_attempts" && (
        <Notice tone="error">{messageFor(failure)}</Notice>
      )}

      {/*
        `noValidate` turns off the browser's own bubble validation in favour of
        the inline messages below. The bubbles are not announced by every
        screen reader, vanish on the next keystroke, and cannot be styled — and
        `required` stays on the inputs regardless, because it is what tells
        assistive technology the field is mandatory.

        There is deliberately no "create an account" link here. Registration is
        per-app and only legal where an operator has set that app's flag, and
        this UI has no way to ask which apps those are — see
        `lib/self-service.ts`. A link would send most people to a form that
        refuses them, which is worse than no link.
      */}
      <form
        className="ward-form"
        noValidate
        onSubmit={(event) => {
          void onSubmit(event);
        }}
      >
        <Field
          id="ward-username"
          label="Username"
          name="username"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          required
          inputRef={usernameRef}
          value={username}
          error={missing.username ? "Enter your username." : undefined}
          disabled={submitting}
          onChange={(event) => {
            setUsername(event.target.value);
          }}
        />
        <Field
          id="ward-password"
          label="Password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          inputRef={passwordRef}
          value={password}
          error={missing.password ? "Enter your password." : undefined}
          disabled={submitting}
          onChange={(event) => {
            setPassword(event.target.value);
          }}
        />
        {/*
          No second copy of the wait beside the button. The notice above already
          says how long, the disabled button already says "not yet", and a
          countdown rendered twice on one screen reads as two different clocks.
        */}
        <div className="ward-actions">
          <button className="ward-button" type="submit" disabled={submitting || lockedOut}>
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </div>
      </form>
    </Threshold>
  );
}
