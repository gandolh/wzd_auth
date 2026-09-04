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
  override readonly name = "WardUnavailableError";
  readonly statusCode = 503;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}
