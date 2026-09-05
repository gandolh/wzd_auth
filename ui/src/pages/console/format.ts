/**
 * Formatting for the console. Pure, and therefore tested directly.
 *
 * Two rules run through all of it. **Nothing here ever throws**: every value
 * comes from an append-only log or a database column that outlives the code
 * reading it, and an operator looking at an audit trail while something is
 * wrong must not be handed a blank screen because one row had an unparseable
 * timestamp. And **nothing here invents precision**: a duration is rounded
 * down, so "14 min" never means fifteen.
 */

/**
 * An ISO-8601 instant as a local wall-clock string, or the raw input if it does
 * not parse.
 *
 * Local rather than UTC because there is exactly one operator and this is the
 * clock on their wall. The raw ISO string always travels alongside it in a
 * `<time dateTime>` attribute and a tooltip, so the unambiguous value is never
 * lost.
 */
export function formatWhen(iso: string): string {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  const pad = (value: number): string => String(value).padStart(2, "0");
  return (
    `${String(at.getFullYear())}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} ` +
    `${pad(at.getHours())}:${pad(at.getMinutes())}`
  );
}

/** Seconds between now and an ISO instant, floored at zero. */
export function secondsUntil(iso: string, now: number = Date.now()): number {
  const at = new Date(iso).getTime();
  if (Number.isNaN(at)) return 0;
  return Math.max(0, Math.floor((at - now) / 1000));
}

/**
 * A coarse countdown: `14 min`, `40 sec`, `expired`.
 *
 * Rounded **down** on purpose. The console shows how long the session has left,
 * and a value rounded up would promise time the server will not honour.
 */
export function formatRemaining(seconds: number): string {
  if (seconds <= 0) return "expired";
  if (seconds < 60) return `${String(seconds)} sec`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${String(minutes)} min`;
  const hours = Math.floor(minutes / 60);
  return `${String(hours)} h ${String(minutes % 60)} min`;
}

/**
 * How long the console session has left, and whether to say so loudly.
 *
 * Two deadlines are enforced server-side — a sliding idle window and a fixed
 * absolute lifetime — and the session dies at whichever comes first, so the
 * honest number is the smaller of the two. Reporting only the idle window would
 * promise time an expiring session does not have.
 */
export function sessionRemaining(
  session: { idleExpiresAt: string; absoluteExpiresAt: string },
  now: number = Date.now(),
): { seconds: number; text: string; low: boolean } {
  const seconds = Math.min(
    secondsUntil(session.idleExpiresAt, now),
    secondsUntil(session.absoluteExpiresAt, now),
  );
  return { seconds, text: formatRemaining(seconds), low: seconds <= 120 };
}

/**
 * An audit row's `detail` as one readable line.
 *
 * `detail` is free-form JSON by design — it carries whatever context an event
 * needs without a migration — so this renders it generically: `key=value` pairs
 * for a flat object, JSON for anything nested. It is bounded because a runaway
 * detail must not push the rest of the row off the screen.
 */
export function formatDetail(detail: unknown, maxLength = 240): string {
  if (detail === null || detail === undefined) return "";
  if (typeof detail !== "object") return clamp(String(detail), maxLength);

  if (Array.isArray(detail)) return clamp(JSON.stringify(detail), maxLength);

  const pairs = Object.entries(detail as Record<string, unknown>).map(([key, value]) => {
    const rendered =
      value === null
        ? "null"
        : typeof value === "object"
          ? JSON.stringify(value)
          : typeof value === "string"
            ? value
            : String(value);
    return `${key}=${rendered}`;
  });
  return clamp(pairs.join("  "), maxLength);
}

function clamp(text: string, maxLength: number): string {
  return text.length <= maxLength ? text : `${text.slice(0, maxLength - 1)}…`;
}

/** `1 grant` / `6 grants`. Counting is worth getting right in a security list. */
export function plural(count: number, one: string, many: string): string {
  return `${String(count)} ${count === 1 ? one : many}`;
}
