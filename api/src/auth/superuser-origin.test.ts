import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * `consoleCookieSecure()` against a plain-HTTP origin on a **real hostname**.
 *
 * Its own file for the reason `routes/auth-loopback.test.ts` documents:
 * `config.ts` resolves its constants once per module registry and vitest gives
 * each test file its own, so a second `WARD_PUBLIC_ORIGIN` cannot be exercised
 * from `superuser.test.ts` (which runs at `https://gandolh.ro`).
 *
 * The finding: `consoleCookieSecure()` used to test
 * `WARD_PUBLIC_ORIGIN.startsWith("https:")` on its own, dropping the loopback
 * half of the rule its own comment described. `config.ts` accepts any
 * well-formed `http:` or `https:` origin and does **not** restrict `http:` to
 * loopback, so for `http://gandolh.ro` its sibling `secureCookiesFor` returned
 * `true` (fail closed — the cookie breaks loudly rather than travelling in the
 * clear) while this returned `false`, shipping the cookie that carries the
 * non-revocable break-glass session over plain HTTP to a real hostname with no
 * `Secure` at all. It now defers to `cookie.ts` rather than reimplementing it.
 *
 * The loopback exception itself is still asserted in `cookie.test.ts` and
 * `routes/auth-loopback.test.ts`; this file asserts the boundary the console
 * cookie was on the wrong side of.
 */

const ORIGIN = "http://gandolh.ro";

let dir: string;
let superuser: typeof import("./superuser.js");
let cookie: typeof import("./cookie.js");

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-superuser-origin-"));

  process.env["PORT"] = "8798";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "unused.db");
  process.env["WARD_ADMIN_USERNAME"] = "break-glass";
  process.env["WARD_ADMIN_PASSWORD"] = "a-long-random-break-glass-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;

  // Dynamic, and after the assignments: `config.ts` validates at import time
  // and calls `process.exit(1)`, so a hoisted static import would take the
  // worker with it.
  superuser = await import("./superuser.js");
  cookie = await import("./cookie.js");
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("plain HTTP on a real hostname", () => {
  it("keeps Secure on the console cookie, exactly as the session cookies do", async () => {
    // The sibling's answer, which was always the right one.
    expect(cookie.secureCookiesFor(ORIGIN)).toBe(true);

    // And now this one agrees, rather than failing open.
    await expect(superuser.consoleCookieSecure()).resolves.toBe(true);

    const header = superuser.consoleSessionSetCookie("wcs_abc", {
      secure: await superuser.consoleCookieSecure(),
    });
    expect(header).toContain("Secure");

    // The clearing cookie has to match, or the browser deletes nothing.
    const cleared = superuser.consoleSessionClearCookie({
      secure: await superuser.consoleCookieSecure(),
    });
    expect(cleared).toContain("Secure");
  });

  it("agrees with wardSecureCookies, because it is the same function", async () => {
    await expect(superuser.consoleCookieSecure()).resolves.toBe(await cookie.wardSecureCookies());
  });
});
