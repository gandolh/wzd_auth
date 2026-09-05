/**
 * Rendering a lockout as a wait rather than as a failure.
 *
 * `429 too_many_attempts` is the one error on the login page where a person can
 * do something concrete, and the concrete thing is *wait a specific length of
 * time*. Brief 09 exists partly because six apps each got this wrong in their
 * own way, and the two wrong answers are worth naming: a generic "sign-in
 * failed" (which invites a seventh attempt, extending the lockout), and a bare
 * "try again later" (which makes an eighty-second wait feel like a ban).
 *
 * So the number is rendered, it counts down, and the submit button is disabled
 * until it reaches zero. `retryAfterSeconds` comes from the response body —
 * Ward repeats it there precisely so a browser client need not read a header.
 */

/**
 * A wait, in words. `95` → `"1 min 35 s"`, `40` → `"40 s"`.
 *
 * Words rather than a `1:35` clock face, because a clock implies a deadline
 * somebody is racing and this is just a pause. Minutes and seconds and nothing
 * larger: the API's ceiling is minutes, and an hours-long value would mean
 * something is broken, in which case a wrong-looking string is a useful signal
 * rather than a thing to format prettily.
 */
export function formatWait(seconds: number): string {
  const total = Math.max(0, Math.ceil(seconds));
  if (total < 60) return `${String(total)} s`;
  const minutes = Math.floor(total / 60);
  const rest = total % 60;
  if (rest === 0) return `${String(minutes)} min`;
  return `${String(minutes)} min ${String(rest)} s`;
}
