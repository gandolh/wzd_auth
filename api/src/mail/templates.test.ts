import { describe, expect, it } from "vitest";

import { verificationLink, verificationMail, WARD_API_PREFIX } from "./templates.js";

/**
 * The templates are pure, so these tests need no environment, no database and
 * no clock — which is the property worth protecting: the moment this file needs
 * a `beforeAll`, something in `templates.ts` has grown a dependency it should
 * not have.
 */

describe("verificationLink", () => {
  /**
   * The prefix is the browser-visible half. Caddy serves Ward with
   * `handle_path /ward-api/*` and strips it, so a link without it 404s in
   * production while every `app.inject()` test passes — the same trap the
   * refresh cookie's `Path` documents.
   */
  it("points at the browser-visible /ward-api path, not the Fastify route", () => {
    const link = verificationLink("https://gandolh.ro", "abc123");
    expect(link).toBe("https://gandolh.ro/ward-api/verify?token=abc123");
    expect(WARD_API_PREFIX).toBe("/ward-api");
  });

  it("percent-encodes the token", () => {
    // Hex tokens have nothing to encode; this asserts the guard that keeps a
    // later change of alphabet from producing links that truncate.
    expect(verificationLink("https://gandolh.ro", "a+b/c=")).toContain("token=a%2Bb%2Fc%3D");
  });
});

describe("verificationMail", () => {
  const mail = verificationMail({
    to: "alice@example.com",
    username: "Alice",
    appName: "Public Resource Map",
    link: "https://gandolh.ro/ward-api/verify?token=deadbeef",
    expiresInHours: 24,
  });

  /**
   * The subject names the **app**, not Ward. Registration happens at an app,
   * and a stranger who signed up at prm has never heard of Ward — a message
   * from an unrecognised service asking them to click a link is
   * indistinguishable from phishing.
   */
  it("names the app in the subject", () => {
    expect(mail.subject).toBe("Confirm your email address for Public Resource Map");
  });

  it("carries the link, the username and the expiry in a plain-text body", () => {
    expect(mail.to).toBe("alice@example.com");
    expect(mail.text).toContain("https://gandolh.ro/ward-api/verify?token=deadbeef");
    expect(mail.text).toContain("Alice");
    expect(mail.text).toContain("24 hours");
    // No HTML part, and no markup in the text one — see the module header.
    expect(mail.text).not.toContain("<");
  });

  it("says the link is single-use, and that ignoring it is a complete response", () => {
    expect(mail.text).toContain("works once");
    expect(mail.text).toContain("you can ignore this message");
  });

  it("agrees on singular and plural hours", () => {
    const one = verificationMail({
      to: "a@b.co",
      username: "a",
      appName: "x",
      link: "l",
      expiresInHours: 1,
    });
    expect(one.text).toContain("after 1 hour.");
  });
});
