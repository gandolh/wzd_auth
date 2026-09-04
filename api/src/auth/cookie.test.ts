import { describe, expect, it } from "vitest";

import {
  ACCESS_COOKIE_MAX_AGE_SECONDS,
  ACCESS_COOKIE_NAME,
  ACCESS_COOKIE_PATH,
  REFRESH_COOKIE_NAME,
  REFRESH_COOKIE_PATH,
  REFRESH_TOKEN_TTL_SECONDS,
  clearedSessionCookies,
  readCookie,
  secureCookiesFor,
  serializeCookie,
  sessionCookies,
} from "./cookie.js";
import { ACCESS_TOKEN_TTL_SECONDS } from "../tokens/claims.js";

/** Parse a `Set-Cookie` value into a name, a value and its attributes. */
function parseSetCookie(header: string): {
  name: string;
  value: string;
  attributes: Map<string, string>;
} {
  const [pair, ...rest] = header.split(";") as [string, ...string[]];
  const eq = pair.indexOf("=");
  const attributes = new Map<string, string>();

  for (const part of rest) {
    const trimmed = part.trim();
    const at = trimmed.indexOf("=");
    if (at === -1) attributes.set(trimmed.toLowerCase(), "");
    else attributes.set(trimmed.slice(0, at).toLowerCase(), trimmed.slice(at + 1));
  }

  return { name: pair.slice(0, eq), value: pair.slice(eq + 1), attributes };
}

describe("the two cookie scopes", () => {
  it("names and paths are the ones the decisions record", () => {
    // `ward_session` at `/ward-api` is recorded in wiki/decisions.md.
    expect(ACCESS_COOKIE_NAME).toBe("ward_session");
    expect(ACCESS_COOKIE_PATH).toBe("/");

    // The refresh cookie's path is the BROWSER-side path, prefix included:
    // Caddy's `handle_path` strips `/ward-api` before Fastify sees the request,
    // so a cookie scoped to `/refresh` would never be sent.
    expect(REFRESH_COOKIE_NAME).toBe("ward_refresh");
    expect(REFRESH_COOKIE_PATH).toBe("/ward-api/refresh");
  });

  it("lifetimes match the decisions: 15 minutes and 30 days", () => {
    expect(ACCESS_COOKIE_MAX_AGE_SECONDS).toBe(ACCESS_TOKEN_TTL_SECONDS);
    expect(ACCESS_COOKIE_MAX_AGE_SECONDS).toBe(15 * 60);
    expect(REFRESH_TOKEN_TTL_SECONDS).toBe(30 * 24 * 60 * 60);
  });
});

describe("sessionCookies", () => {
  const [access, refresh] = sessionCookies({
    accessToken: "header.payload.signature",
    refreshToken: "a".repeat(64),
    secure: true,
  });

  it("scopes the access cookie to the whole origin", () => {
    const parsed = parseSetCookie(access);

    expect(parsed.name).toBe("ward_session");
    expect(parsed.value).toBe("header.payload.signature");
    expect(parsed.attributes.get("path")).toBe("/");
    expect(parsed.attributes.has("httponly")).toBe(true);
    expect(parsed.attributes.get("samesite")).toBe("Lax");
    expect(parsed.attributes.has("secure")).toBe(true);
    expect(parsed.attributes.get("max-age")).toBe(String(15 * 60));
  });

  it("scopes the refresh cookie to the one endpoint that consumes it", () => {
    const parsed = parseSetCookie(refresh);

    expect(parsed.name).toBe("ward_refresh");
    expect(parsed.attributes.get("path")).toBe("/ward-api/refresh");
    expect(parsed.attributes.has("httponly")).toBe(true);
    expect(parsed.attributes.get("samesite")).toBe("Lax");
    expect(parsed.attributes.has("secure")).toBe(true);
    expect(parsed.attributes.get("max-age")).toBe(String(30 * 24 * 60 * 60));
  });

  it("honours a shorter refresh Max-Age, so the cookie cannot outlive its row", () => {
    const [, shortened] = sessionCookies({
      accessToken: "a.b.c",
      refreshToken: "b".repeat(64),
      secure: true,
      refreshMaxAgeSeconds: 3600,
    });

    expect(parseSetCookie(shortened).attributes.get("max-age")).toBe("3600");
  });

  it("omits Secure when told to", () => {
    const [plainAccess, plainRefresh] = sessionCookies({
      accessToken: "a.b.c",
      refreshToken: "c".repeat(64),
      secure: false,
    });

    expect(parseSetCookie(plainAccess).attributes.has("secure")).toBe(false);
    expect(parseSetCookie(plainRefresh).attributes.has("secure")).toBe(false);
    // Everything else is unconditional.
    expect(parseSetCookie(plainAccess).attributes.has("httponly")).toBe(true);
    expect(parseSetCookie(plainRefresh).attributes.get("samesite")).toBe("Lax");
  });
});

describe("clearedSessionCookies", () => {
  it("matches the original path and Secure flag, or the browser keeps the original", () => {
    const [access, refresh] = clearedSessionCookies({ secure: true });
    const [live] = sessionCookies({ accessToken: "a.b.c", refreshToken: "d", secure: true });

    const cleared = parseSetCookie(access);
    const original = parseSetCookie(live);

    // A cleared cookie whose Path or Secure differs is a DIFFERENT cookie to
    // the browser, and the original survives — "logout doesn't log out".
    expect(cleared.name).toBe(original.name);
    expect(cleared.attributes.get("path")).toBe(original.attributes.get("path"));
    expect(cleared.attributes.has("secure")).toBe(original.attributes.has("secure"));

    expect(cleared.value).toBe("");
    expect(cleared.attributes.get("max-age")).toBe("0");
    expect(cleared.attributes.get("expires")).toContain("1970");

    expect(parseSetCookie(refresh).attributes.get("path")).toBe("/ward-api/refresh");
    expect(parseSetCookie(refresh).attributes.get("max-age")).toBe("0");
  });
});

describe("serializeCookie", () => {
  it("refuses a value that a browser would silently truncate", () => {
    expect(() => serializeCookie({ name: "x", value: "a b", path: "/", secure: true })).toThrow(
      TypeError,
    );
    expect(() => serializeCookie({ name: "x", value: "a;b", path: "/", secure: true })).toThrow(
      TypeError,
    );
    expect(() => serializeCookie({ name: "a b", value: "x", path: "/", secure: true })).toThrow(
      TypeError,
    );
  });

  it("does not put the value in the error message", () => {
    // The value is always a token, and the message ends up in a log.
    try {
      serializeCookie({ name: "ward_session", value: "secret token", path: "/", secure: true });
      expect.unreachable();
    } catch (error) {
      expect((error as Error).message).not.toContain("secret token");
      expect((error as Error).message).toContain("ward_session");
    }
  });

  it("accepts the shapes Ward actually emits", () => {
    // A compact JWS (base64url plus dots) and a hex refresh token.
    expect(() =>
      serializeCookie({ name: "ward_session", value: "eyJ.eyJ.a-b_c", path: "/", secure: true }),
    ).not.toThrow();
    expect(() =>
      serializeCookie({ name: "ward_refresh", value: "0f".repeat(32), path: "/", secure: true }),
    ).not.toThrow();
  });
});

describe("readCookie", () => {
  it("finds a cookie among others", () => {
    const header = "theme=dark; ward_session=a.b.c; ward_refresh=deadbeef";

    expect(readCookie(header, "ward_session")).toBe("a.b.c");
    expect(readCookie(header, "ward_refresh")).toBe("deadbeef");
    expect(readCookie(header, "nope")).toBeUndefined();
  });

  it("treats a cleared cookie as absent", () => {
    // A client that ignored the expiry still sends `ward_refresh=`.
    expect(readCookie("ward_refresh=", "ward_refresh")).toBeUndefined();
    expect(readCookie("ward_refresh=  ", "ward_refresh")).toBeUndefined();
  });

  it("does not match a name by prefix or suffix", () => {
    expect(readCookie("xward_session=nope", "ward_session")).toBeUndefined();
    expect(readCookie("ward_session_extra=nope", "ward_session")).toBeUndefined();
  });

  it("takes the first occurrence, which is the more specific path", () => {
    expect(readCookie("ward_session=real; ward_session=shadow", "ward_session")).toBe("real");
  });

  it("handles a missing header and an array header", () => {
    expect(readCookie(undefined, "ward_session")).toBeUndefined();
    expect(readCookie(["a=1", "ward_session=a.b.c"], "ward_session")).toBe("a.b.c");
  });
});

describe("secureCookiesFor", () => {
  it("sets Secure for any https origin", () => {
    expect(secureCookiesFor("https://gandolh.ro")).toBe(true);
    expect(secureCookiesFor("https://localhost:8443")).toBe(true);
  });

  it("omits Secure only for plain HTTP on loopback", () => {
    // Without this exception nobody can run the login flow locally: a browser
    // does not store a Secure cookie over http://127.0.0.1 at all.
    expect(secureCookiesFor("http://127.0.0.1:8787")).toBe(false);
    expect(secureCookiesFor("http://localhost:5173")).toBe(false);
    expect(secureCookiesFor("http://[::1]:8787")).toBe(false);
  });

  it("still sets Secure for plain HTTP on a real host — the dangerous case", () => {
    // A session cookie crossing a network in the clear is the failure this must
    // not enable. It fails closed: the cookie is simply not stored.
    expect(secureCookiesFor("http://gandolh.ro")).toBe(true);
    expect(secureCookiesFor("http://192.168.1.10:8787")).toBe(true);
  });

  it("fails closed on a value config would never have produced", () => {
    expect(secureCookiesFor("not a url")).toBe(true);
    expect(secureCookiesFor("")).toBe(true);
  });
});
