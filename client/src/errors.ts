/**
 * The error taxonomy this package throws.
 *
 * Kept in one file because a Fastify (or any framework's) error handler wants
 * to `instanceof`-switch on exactly these three, and `statusCode` is set on
 * each so Fastify's *default* error handler already does the right thing with
 * no extra wiring.
 */

/**
 * A token that does not verify: malformed, unsigned, wrong algorithm, signed
 * by an unknown key, expired, or carrying the wrong issuer/audience. This is
 * an authentication failure and maps to `401`.
 */
export class WardAuthenticationError extends Error {
  override readonly name = "WardAuthenticationError";
  readonly statusCode = 401;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * The token verified and the session is live, but the subject does not hold
 * the role a route requires. Maps to `403`.
 */
export class WardForbiddenError extends Error {
  override readonly name = "WardForbiddenError";
  readonly statusCode = 403;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * Ward could not be reached, or answered something other than its documented
 * `200`/`no-store` contract (a `500`, a timeout, a network error, an
 * unparsable body). This is deliberately **not** the same as an inactive
 * session.
 *
 * `corpus/wiki/decisions-tokens.md`: Ward being down already means nobody can
 * log in; it must not *also* mean revocation silently stops working by having
 * every caller fall back to treating "I don't know" as "yes". Every call site
 * in this package that can throw this must fail the request closed — reject,
 * never serve a cached or default-active answer. Maps to `503` by default so
 * a consumer's monitoring can tell "Ward is broken" apart from "this person is
 * not signed in".
 */
export class WardUnavailableError extends Error {
  /**
   * Widened to `string` rather than left as the literal, because
   * `WardConfigurationError` extends this class and must be able to name
   * itself. Nothing branches on this value — `instanceof` is how both classes
   * are told apart, and it keeps working across the subclass — so the literal
   * bought nothing but the constraint.
   */
  override readonly name: string = "WardUnavailableError";
  readonly statusCode = 503;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * Ward refused this app's key: `POST /introspect` answered `401`.
 *
 * A **subclass of `WardUnavailableError`**, deliberately. Every call site in
 * this package and in every consuming app already fails closed on
 * `WardUnavailableError`, and that behaviour is exactly right here — an app that
 * cannot introspect must reject requests, not admit them — so making this a
 * sibling would mean six apps each needing a new `catch` before the fix was
 * safe. Subclassing means the safe behaviour is inherited and the extra
 * information is available to whoever wants it.
 *
 * What it adds is diagnosability, which is the entire point. Every other reason
 * for a failed introspection is transient and about Ward: a timeout, a restart,
 * a 500. This one is permanent and about **this app's configuration** — its
 * `WARD_APP_KEY` is absent, wrong, or has been revoked in Ward's console — and
 * no amount of retrying or waiting will change it. Reading
 * "introspect returned unexpected status 401" in a log at 3am, and having to
 * work out that Ward is fine and it is your own deployment that is broken, is a
 * bad half hour this class exists to prevent.
 *
 * Keeps `statusCode` 503: to the app's own callers this is still "the identity
 * service is not usable from here", and a `401` passed through would tell a
 * *user* they are not signed in when the truth is that the server is
 * misconfigured.
 */
export class WardConfigurationError extends WardUnavailableError {
  override readonly name = "WardConfigurationError";

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}
