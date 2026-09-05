import { describe, expect, it } from "vitest";

import {
  verificationLink,
  verificationMail,
  WARD_API_PREFIX,
  WARD_UI_VERIFY_PATH,
} from "./templates.js";

/**
 * The templates are pure, so these tests need no environment, no database and
 * no clock — which is the property worth protecting: the moment this file needs
 * a `beforeAll`, something in `templates.ts` has grown a dependency it should
 * not have.
 */

describe("verificationLink", () => {
  /**
   * **The link goes to the UI screen, not to the API route.**
   *
   * Both pages verify an address, and for a while this pointed at
   * `/ward-api/verify` — the API's own server-rendered page — which meant
   * brief 09's `/ward/verify` screen was built for a moment nobody reached.
   * The API route is deliberately kept (a non-browser client uses it, and it is
   * content-negotiated for exactly that); only the URL a person is mailed
   * moved.
   *
   * Both paths are still **browser-visible** halves. Caddy serves Ward with
   * `handle_path /ward-api/*` and strips it, so a link spelled the Fastify way
   * 404s in production while every `app.inject()` test passes — the same trap
   * the refresh cookie's `Path` documents.
   */
  it("points at the UI verification screen, not at the API route", () => {
    const link = verificationLink("https://gandolh.ro", "abc123");
    expect(link).toBe("https://gandolh.ro/ward/verify?token=abc123");
    expect(WARD_UI_VERIFY_PATH).toBe("/ward/verify");
    // Still exported, because the API route it names has not moved.
    expect(WARD_API_PREFIX).toBe("/ward-api");
    expect(link).not.toContain("/ward-api/");
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
    link: "https://gandolh.ro/ward/verify?token=deadbeef",
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
    expect(mail.text).toContain("https://gandolh.ro/ward/verify?token=deadbeef");
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
