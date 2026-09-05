import { ESTATE_ROOTS } from "./estate.js";

/**
 * `?next=` validation — the one piece of security-relevant logic in this UI.
 *
 * An open redirect on the estate's central login page is the worst possible
 * place to have one. It is a phishing primitive that borrows Ward's own URL,
 * its own TLS certificate and the person's own habit of typing a password
 * there: `https://gandolh.ro/ward/login?next=https://evil.example` is a link
 * that looks exactly like the real thing, and the moment the credential is
 * accepted the browser is somewhere else entirely.
 *
 * So the rule is not "reject `http://`". The rule is **an accepted value is a
 * path on this origin, under a first segment that names a real app, and
 * nothing else is accepted.** Everything below exists because there are a
 * surprising number of strings that are not that, and look like they are.
 *
 * ## The rules, in order
 *
 *  1. **Present and non-empty**, after trimming nothing — a value that needs
 *     trimming is a value somebody built wrong, and rule 4 refuses it.
 *  2. **At most `MAX_NEXT_LENGTH` characters.** Nothing legitimate is longer,
 *     and the decode loop below should not be handed unbounded input.
 *  3. **No backslash, anywhere.** `/\evil.example` is normalised to
 *     `//evil.example` by some URL consumers, which is a protocol-relative URL
 *     to another host. This is checked as a character ban rather than handled
 *     by the parser, because the set of consumers that normalise it is not one
 *     this code controls.
 *  4. **No control characters and no whitespace in the raw value; no control
 *     characters in the decoded one.** `\t`, `\n` and
 *     `\r` are *stripped* from URLs by the WHATWG parser before anything else
 *     happens, so `/\t/evil.example` and `/%09//evil.example` are ways of
 *     writing a string whose meaning changes between the check and the use.
 *     Ordinary spaces are banned in the same breath: a legitimate `?next=`
 *     percent-encodes them.
 *  5. **Percent-decodes cleanly, and the decoded form obeys 3–7 too.** Up to
 *     `DECODE_PASSES` passes, because `%252f` decodes to `%2f` decodes to `/`.
 *     A value that does not decode (a stray `%`) is refused rather than
 *     guessed at.
 *  6. **Starts with exactly one `/`.** One leading slash makes a scheme
 *     impossible (`https:` and `javascript:` both fail here, not later), and
 *     refusing two rejects the protocol-relative `//evil.example` — the single
 *     most common way this check is got wrong, because it *is* a path by most
 *     naive definitions.
 *  7. **Resolves, against a sentinel origin, to that same origin** — and so
 *     does its decoded form. Belt and braces over rule 6, and the resolution
 *     is what collapses `..` so rule 8 cannot be walked around.
 *  8. **The resolved first path segment is in `ESTATE_ROOTS`** — exactly, not
 *     as a prefix — for both the raw and the decoded resolution. `/` alone is
 *     accepted as the estate's apex. This is the allowlist proper; rules 3–7
 *     only establish that there is a path to look up.
 *  9. **Not the sign-in page itself.** `?next=/ward/login` is a loop, and a
 *     loop on the login page reads as "my password did not work".
 *
 * Anything refused resolves to `DEFAULT_NEXT` **silently**. A person who
 * followed a bad link needs to sign in, not to read a diagnostic about the
 * link; and an attacker probing which of nine rules caught them learns nothing
 * they cannot learn from the source, which is public. The `reason` is returned
 * for tests and for a `debug` log line, and is never rendered.
 *
 * ## What this deliberately does not do
 *
 * It does not consult the network, and it does not check that the path exists.
 * A `?next=` naming an app that is not deployed yet lands on a 404 inside the
 * estate — which is a broken link, not a security event, and is somebody
 * else's bug to fix.
 */

/** Where a refused, absent or unusable `next` sends somebody. */
export const DEFAULT_NEXT = "/";

/**
 * The login page's own path on the origin, for the loop check.
 *
 * Spelled out rather than derived from the router's basename because this
 * module is pure and testable, and because the two would have to be kept in
 * step either way.
 */
export const WARD_LOGIN_PATH = "/ward/login";

/** Long enough for a real deep link with a query string, short enough to bound. */
export const MAX_NEXT_LENGTH = 512;

/** `%252f` → `%2f` → `/` is two passes; the third proves the value settled. */
const DECODE_PASSES = 3;

/**
 * An origin no host can ever be, so a value that reaches it did so by being
 * relative. `.invalid` is reserved by RFC 2606 for exactly this.
 */
const SENTINEL_BASE = "https://ward.invalid";

/** Why a value was refused. For tests and logs; never shown to a person. */
export type NextRejection =
  | "absent"
  | "too_long"
  | "backslash"
  | "control_or_space"
  | "undecodable"
  | "not_absolute_path"
  | "protocol_relative"
  | "off_origin"
  | "unknown_root"
  | "sign_in_loop";

export type NextDecision =
  | {
      readonly accepted: true;
      /** Safe to hand to `location.assign`. Normalised: `..` collapsed. */
      readonly path: string;
      /** The resolved first path segment, or `""` for the apex. */
      readonly root: string;
    }
  | {
      readonly accepted: false;
      /** Always `DEFAULT_NEXT`, so a caller may use `path` unconditionally. */
      readonly path: typeof DEFAULT_NEXT;
      readonly reason: NextRejection;
    };

/**
 * Every kind of whitespace, plus C0 and DEL. Applied to the **raw** value.
 *
 * `\u0000-\u0020` covers C0 and the space itself, `\u007f` is DEL, and `\s` adds
 * NBSP, the en/em spaces, the line separators and the BOM. A raw tab, newline
 * or carriage return is *stripped* by the WHATWG URL parser before anything
 * else happens, so `/\t/evil.example` means one thing to a `startsWith("//")`
 * check and another to the parser; the rest are banned in the same breath
 * because a legitimate `?next=` percent-encodes any space it carries.
 */
// eslint-disable-next-line no-control-regex
const FORBIDDEN_RAW = /[\u0000-\u0020\u007f\s]/u;

/**
 * C0 and DEL only. Applied to the **decoded** value.
 *
 * Deliberately narrower than `FORBIDDEN_RAW`, and the difference is the whole
 * reason there are two: `%20` is a *legitimate* encoded space in a path, so
 * re-applying the whitespace ban after decoding would refuse
 * `/atrium/My%20Book` — a real link shape — for no gain, since an encoded
 * space is never stripped and never changes how anything routes. A decoded
 * control character has no legitimate use at all, and a decoded NUL truncates
 * the string in enough consumers to be worth refusing on its own.
 */
// eslint-disable-next-line no-control-regex
const FORBIDDEN_DECODED = /[\u0000-\u001f\u007f]/u;

function refuse(reason: NextRejection): NextDecision {
  return { accepted: false, path: DEFAULT_NEXT, reason };
}

/**
 * Rules 3, 4 and 6 over a bare string.
 *
 * `forbidden` is the parameter that differs between the raw and the decoded
 * pass; everything else about the shape of an acceptable value is the same in
 * both, and having one function say so is what keeps the two passes from
 * drifting into checking different things.
 */
function shapeOf(value: string, forbidden: RegExp): NextRejection | undefined {
  if (value.includes("\\")) return "backslash";
  if (forbidden.test(value)) return "control_or_space";
  if (!value.startsWith("/")) return "not_absolute_path";
  if (value.startsWith("//")) return "protocol_relative";
  return undefined;
}

/**
 * Rules 7 and 8 — resolve against the sentinel and check the first segment.
 *
 * Run over the raw value **and** its decoded form. The two can disagree:
 * `/atrium/%2e%2e/%2e%2e/evil` resolves with its first segment intact, because
 * the URL parser does not treat a percent-encoded dot as a dot segment, while
 * its decoded form resolves to `/evil`. Requiring both to pass is what stops
 * an encoded traversal from borrowing an allowlisted root.
 */
function resolvedRoot(value: string): { root: string; path: string } | NextRejection {
  let url: URL;
  try {
    url = new URL(value, SENTINEL_BASE);
  } catch {
    return "off_origin";
  }
  if (url.origin !== SENTINEL_BASE) return "off_origin";

  if (url.pathname === WARD_LOGIN_PATH || url.pathname.startsWith(`${WARD_LOGIN_PATH}/`)) {
    return "sign_in_loop";
  }

  // `"/x/y".split("/")` is `["", "x", "y"]`, so index 1 is the first segment
  // and is `""` for the apex `"/"` — which is allowed, and is the only empty
  // root there is.
  const root = url.pathname.split("/")[1] ?? "";
  if (root !== "" && !ESTATE_ROOTS.has(root)) return "unknown_root";

  return { root, path: `${url.pathname}${url.search}${url.hash}` };
}

/**
 * Validate a raw `?next=` value.
 *
 * `null` and `undefined` are ordinary inputs — `URLSearchParams.get` returns
 * `null` for a parameter that is not there — so the caller does not have to
 * branch before calling.
 */
export function resolveNext(raw: string | null | undefined): NextDecision {
  if (raw === null || raw === undefined || raw === "") return refuse("absent");
  if (raw.length > MAX_NEXT_LENGTH) return refuse("too_long");

  const rawShape = shapeOf(raw, FORBIDDEN_RAW);
  if (rawShape !== undefined) return refuse(rawShape);

  // Rule 5. Decode to a fixed point, re-checking the shape at every step, so a
  // value cannot pass the checks in one encoding and mean something else in
  // another.
  let decoded = raw;
  for (let pass = 0; pass < DECODE_PASSES; pass += 1) {
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return refuse("undecodable");
    }
    if (next === decoded) break;
    decoded = next;
    const shape = shapeOf(decoded, FORBIDDEN_DECODED);
    if (shape !== undefined) return refuse(shape);
  }

  const rawResolved = resolvedRoot(raw);
  if (typeof rawResolved === "string") return refuse(rawResolved);

  const decodedResolved = resolvedRoot(decoded);
  if (typeof decodedResolved === "string") return refuse(decodedResolved);

  return { accepted: true, path: rawResolved.path, root: rawResolved.root };
}

/**
 * The login URL **on the origin**, with `next` set — `/ward/login?next=…`.
 *
 * This is the shape an app outside Ward needs: briefs 13–15 add "sign in with
 * Ward" links, and this is the string they build (or copy). The value is
 * encoded here so a caller cannot forget to, which is the mistake that makes a
 * deep link with a query string silently lose everything after its first `&`.
 */
export function loginUrlFor(next: string): string {
  return `${WARD_LOGIN_PATH}?next=${encodeURIComponent(next)}`;
}

/**
 * The router basename. Ward's SPA is mounted at `/ward`, and Vite's `base`
 * matches, so React Router paths are relative to it.
 */
export const WARD_BASENAME = "/ward";

/**
 * The same login URL **as a router path** — `/login?next=…`.
 *
 * Two functions rather than one because getting this wrong is silent and
 * annoying: `<Link to="/ward/login">` under a `/ward` basename navigates to
 * `/ward/ward/login`, and a 404 inside your own SPA looks like a routing bug
 * three files away. Use this one inside Ward's UI, `loginUrlFor` outside it.
 */
export function loginRouteFor(next: string): string {
  return loginUrlFor(next).slice(WARD_BASENAME.length);
}
