import { useCallback, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { Field } from "../components/Field.js";
import { Notice } from "../components/Notice.js";
import { Threshold } from "../components/Threshold.js";
import { WardApiError, register, type RegisterResult, type WardErrorCode } from "../lib/api.js";
import { appName } from "../lib/estate.js";
import { loginRouteFor } from "../lib/next.js";
import { useOpenApps } from "../lib/open-apps.js";
import { deadlineIn, useCountdown } from "../lib/use-countdown.js";
import { formatWait } from "../lib/wait.js";

/**
 * `/ward/register?app=<slug>` — signing up at one app.
 *
 * ## Registration is per-app, and the app is named
 *
 * Anyone may register; registering confers **that app's baseline role and
 * nothing else**, and reaching anything further needs a grant. So "sign up for
 * Ward" is not a thing that exists, and a form that did not say which app it
 * was for would be describing something the API cannot do. The slug comes from
 * `?app=`, and without it this page has nothing to offer and says so.
 *
 * The app's *display name* comes from `GET /ward-api/apps` when that app is
 * one of the open ones — `useOpenApps` fetches it, and `apps.name` is finally
 * readable without the superuser console. `lib/estate.ts`'s hard-coded table
 * is the fallback for everything the open-apps list cannot say anything
 * about: a closed app (the endpoint says nothing about those at all, by
 * design) and a slug this UI has never heard of either way. An unrecognised
 * slug falls all the way through to being shown as the slug — more use to
 * somebody signing up than "Unknown app".
 *
 * ## `registration_closed` is a state, not an error — and now often known early
 *
 * It covers a closed app and an app that does not exist, identically, so the
 * endpoint is not also an app-discovery oracle. When the open-apps list has
 * loaded and this slug is not in it, the page says so **before** the form is
 * filled rather than waiting for a submit to find out; a submit answering
 * `403` regardless is kept as the fallback, because the two lists can
 * disagree for the length of one request. And **apps are not seeded**: a
 * fresh estate answers `registration_closed` to everything until somebody
 * creates an app in the console. That is correct behaviour that looks exactly
 * like a bug, so it is rendered as information — no red, no "error" — and the
 * form is withdrawn rather than left there to be resubmitted.
 *
 * ## `username_taken` is stated plainly, and it is the likely answer
 *
 * The API's own reasoning: the oracle cannot be closed, because the username
 * *is* the identifier and a duplicate has to be refused. Being vague costs
 * every real person the one thing they need to know, in the most likely
 * response this endpoint gives, and costs a prober nothing. What is withheld is
 * everything else — the answer is byte-identical whether the holder is
 * disabled, verified, owner-issued or the break-glass name — and there is
 * deliberately **no "email already registered"** error at all.
 */

/** The three fields, in tab order — which is the order to focus the first gap in. */
type FieldName = "username" | "email" | "password";
const FIELD_ORDER: readonly FieldName[] = ["username", "email", "password"];

function messageFor(code: WardErrorCode): string {
  switch (code) {
    case "username_taken":
      return "That username is taken. Try another one.";
    case "password_too_short":
      return "Passwords need at least 8 characters.";
    case "password_too_long":
      return "That password is too long. Use fewer than 1024 characters.";
    case "invalid_request":
      return "Check the form: a username with no unusual spacing, and a real email address.";
    case "unreachable":
      return "Ward isn't answering. Check your connection and try again.";
    default:
      return "Signing up didn't work. Try again in a moment.";
  }
}

export function Register(): React.JSX.Element {
  const [params] = useSearchParams();
  const slug = params.get("app")?.trim() ?? "";

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [failure, setFailure] = useState<WardErrorCode | undefined>();
  const [closed, setClosed] = useState(false);
  const [created, setCreated] = useState<RegisterResult | undefined>();
  const [lockedUntil, setLockedUntil] = useState<number | undefined>();

  const [missing, setMissing] = useState<Record<FieldName, boolean>>({
    username: false,
    email: false,
    password: false,
  });

  const waitLeft = useCountdown(lockedUntil);
  const lockedOut = lockedUntil !== undefined && waitLeft > 0;

  const openApps = useOpenApps();
  const openEntry = Array.isArray(openApps) ? openApps.find((app) => app.slug === slug) : undefined;
  const name = openEntry?.name ?? appName(slug);
  // Only once the list has actually loaded — while it is `"loading"` this is
  // `false` and the form renders as it always did, so a slow fetch cannot
  // flash "closed" at somebody before it resolves.
  const knownClosed = Array.isArray(openApps) && slug !== "" && openEntry === undefined;

  const usernameRef = useRef<HTMLInputElement>(null);
  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  // Kept for `onSubmit` below, which reads `.current` in an event handler —
  // not during render, so not the thing being worked around here.
  const refs: Record<FieldName, React.RefObject<HTMLInputElement | null>> = {
    username: usernameRef,
    email: emailRef,
    password: passwordRef,
  };

  // `Field`'s `inputRef` is an ordinary prop, not the JSX `ref` attribute
  // React special-cases, so handing it a `RefObject` directly reads as a plain
  // render-time use of a ref value to `react-hooks/refs` — the same object
  // would still be read again on every future render. A memoized callback ref
  // sidesteps that: writing `.current` only happens when React itself invokes
  // the callback to attach or detach the DOM node, which is exactly the
  // "outside of render" case the rule allows, and the stable identity from
  // `useCallback` means React calls it once per mount rather than on every
  // re-render.
  const setUsernameRef = useCallback((node: HTMLInputElement | null) => {
    usernameRef.current = node;
  }, []);
  const setEmailRef = useCallback((node: HTMLInputElement | null) => {
    emailRef.current = node;
  }, []);
  const setPasswordRef = useCallback((node: HTMLInputElement | null) => {
    passwordRef.current = node;
  }, []);

  /**
   * No `?app=`, so there is nothing to sign up for.
   *
   * Rendered as a wrong turn rather than as an error, because that is what it
   * is: registration starts from the app, and somebody who typed
   * `/ward/register` by hand has arrived at a form with no subject.
   */
  if (slug === "") {
    return (
      <Threshold>
        <h1>Which app?</h1>
        <p className="ward-lede">
          Signing up happens at an app, not at Ward — an account carries that app's starting role
          and nothing else. Start from the app you want to join and it will send you back here.
        </p>
        <p className="ward-prose">
          <Link className="ward-link" to="/login">
            Already have an account? Sign in
          </Link>
        </p>
      </Threshold>
    );
  }

  if (created !== undefined) {
    return (
      <Threshold
        footer={
          <>
            Signed up for {name}.{" "}
            <Link className="ward-link" to={loginRouteFor(`/${slug}`)}>
              Sign in
            </Link>
          </>
        }
      >
        <h1>Account created</h1>
        <p className="ward-lede">
          You're registered at {name} as <strong>{created.username}</strong> with the {created.role}{" "}
          role. Signing up doesn't sign you in — do that next.
        </p>
        {created.verificationSent ? (
          <Notice tone="info">
            {/*
              Confirming does not gate anything, and saying so here is the
              honest framing: it stops somebody sitting in their inbox waiting
              for permission to use the app they just joined. It also matters
              because the link expires in 24 hours and **there is no way to send
              another one** — see `Verify`.
            */}
            We've sent a confirmation link to {created.email}. Your account already works; the link
            only confirms the address, and it's good for 24 hours.
          </Notice>
        ) : (
          <Notice tone="wait">
            Your account is ready, but the confirmation email didn't go out. Nothing is blocked by
            that — sign in and carry on.
          </Notice>
        )}
        <p className="ward-prose ward-prose--spaced">
          <Link className="ward-link" to={loginRouteFor(`/${slug}`)}>
            Sign in to {name}
          </Link>
        </p>
      </Threshold>
    );
  }

  if (closed || knownClosed) {
    return (
      <Threshold>
        <h1>{name} isn't taking signups</h1>
        <p className="ward-lede">
          Accounts for {name} are handed out by whoever runs the estate rather than created here.
          Ask them for one — and if you already have an account, it works everywhere.
        </p>
        <p className="ward-prose">
          <Link className="ward-link" to={loginRouteFor(`/${slug}`)}>
            Sign in instead
          </Link>
        </p>
      </Threshold>
    );
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (submitting || lockedOut) return;

    /**
     * The three fields, checked here for emptiness only.
     *
     * `noValidate` turns off the browser's bubbles, so without this an empty
     * submit posts three empty strings and comes back `invalid_request` — a
     * round trip, a lockout-budget spend, and a message about spacing rules
     * that has nothing to do with what happened. Focus moves to the first
     * empty field for the same reason it does on the login page: a keyboard or
     * screen-reader user is otherwise told, from the submit button, that
     * something they cannot see is wrong.
     *
     * Nothing else is checked client-side. The username's spacing rule and the
     * address's format are the API's to judge, and a rule enforced in two
     * places disagrees with itself eventually.
     */
    const blank: Record<FieldName, boolean> = {
      username: username.trim() === "",
      email: email.trim() === "",
      password: password === "",
    };
    setMissing(blank);
    const firstBlank = FIELD_ORDER.find((field) => blank[field]);
    if (firstBlank !== undefined) {
      setFailure(undefined);
      refs[firstBlank].current?.focus();
      return;
    }

    setSubmitting(true);
    setFailure(undefined);
    try {
      setCreated(
        await register({
          app: slug,
          username: username.trim(),
          email: email.trim(),
          password,
        }),
      );
    } catch (error) {
      const code = error instanceof WardApiError ? error.code : "unexpected";
      if (code === "registration_closed") {
        setClosed(true);
      } else if (code === "too_many_attempts") {
        const seconds = error instanceof WardApiError ? (error.retryAfterSeconds ?? 60) : 60;
        setLockedUntil(deadlineIn(seconds));
        setFailure(code);
      } else {
        setFailure(code);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Threshold
      footer={
        <Link className="ward-link" to={loginRouteFor(`/${slug}`)}>
          Already have an account? Sign in
        </Link>
      }
    >
      <h1>Join {name}</h1>
      <p className="ward-lede">
        This creates one Ward account, which signs you in to every app here. It gives you access to{" "}
        {name} and nothing else until somebody grants more.
      </p>

      {lockedOut && (
        <Notice tone="wait">
          Too many signups from your network. Try again in <strong>{formatWait(waitLeft)}</strong>.
        </Notice>
      )}
      {failure !== undefined && failure !== "too_many_attempts" && (
        <Notice tone="error">{messageFor(failure)}</Notice>
      )}

      <form
        className="ward-form"
        noValidate
        onSubmit={(event) => {
          void onSubmit(event);
        }}
      >
        <Field
          id="ward-reg-username"
          label="Username"
          name="username"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          required
          inputRef={setUsernameRef}
          value={username}
          error={missing.username ? "Enter a username." : undefined}
          hint="How you'll sign in. Letters, digits and single spaces."
          disabled={submitting}
          onChange={(event) => {
            setUsername(event.target.value);
          }}
        />
        <Field
          id="ward-reg-email"
          label="Email"
          name="email"
          type="email"
          autoComplete="email"
          autoCapitalize="none"
          spellCheck={false}
          required
          inputRef={setEmailRef}
          value={email}
          error={missing.email ? "Enter an email address." : undefined}
          hint="For confirming the address. It isn't how you sign in."
          disabled={submitting}
          onChange={(event) => {
            setEmail(event.target.value);
          }}
        />
        <Field
          id="ward-reg-password"
          label="Password"
          name="password"
          type="password"
          /*
           * `new-password`, not `current-password`. It is what makes a password
           * manager offer to generate one and save it — and on this page that
           * matters more than usual, because Ward has no password reset: a
           * forgotten password on an owner-issued account has no recovery
           * channel at all.
           */
          autoComplete="new-password"
          required
          minLength={8}
          inputRef={setPasswordRef}
          value={password}
          error={missing.password ? "Choose a password." : undefined}
          hint="At least 8 characters."
          disabled={submitting}
          onChange={(event) => {
            setPassword(event.target.value);
          }}
        />
        <div className="ward-actions">
          <button className="ward-button" type="submit" disabled={submitting || lockedOut}>
            {submitting ? "Creating account…" : `Join ${name}`}
          </button>
        </div>
      </form>
    </Threshold>
  );
}
