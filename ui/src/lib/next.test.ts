import { describe, expect, it } from "vitest";

import {
  DEFAULT_NEXT,
  MAX_NEXT_LENGTH,
  loginUrlFor,
  resolveNext,
  type NextRejection,
} from "./next.js";

/**
 * The `?next=` allowlist, table-driven.
 *
 * This is the highest-value test in brief 09 and the table is meant to be
 * *added to* rather than admired: every string somebody thinks of that ought to
 * be refused belongs in the rejection table, and the cost of a new row is one
 * line. An open redirect here is a phishing primitive wearing Ward's own
 * certificate, so the bar is "we tried to break it and wrote down what we
 * tried", not "the happy path works".
 *
 * The `reason` is asserted as well as the refusal. Not because a caller reads
 * it — nothing renders it — but because a rule that stops catching what it was
 * written for should fail loudly rather than be covered by the rule after it.
 * A refusal that moves from `protocol_relative` to `unknown_root` is still a
 * refusal and is still a change worth seeing.
 */

const ACCEPTED: ReadonlyArray<{ input: string; path: string; root: string; why: string }> = [
  { input: "/atrium/", path: "/atrium/", root: "atrium", why: "the acceptance criterion" },
  { input: "/atrium", path: "/atrium", root: "atrium", why: "a root with no trailing slash" },
  { input: "/", path: "/", root: "", why: "the estate apex" },
  {
    input: "/atrium/book/17?page=3",
    path: "/atrium/book/17?page=3",
    root: "atrium",
    why: "a deep link keeps its query string",
  },
  {
    input: "/atrium/reader#chapter-4",
    path: "/atrium/reader#chapter-4",
    root: "atrium",
    why: "a fragment survives; it never leaves the browser anyway",
  },
  {
    input: "/prm/map?lat=45.7&lng=21.2",
    path: "/prm/map?lat=45.7&lng=21.2",
    root: "prm",
    why: "an ampersand is not a delimiter once the value is decoded",
  },
  {
    input: "/imbatranim-os/settings",
    path: "/imbatranim-os/settings",
    root: "imbatranim-os",
    why: "a hyphenated root is one segment",
  },
  {
    input: "/ward/account",
    path: "/ward/account",
    root: "ward",
    why: "Ward's own pages are estate paths — self-service links to them",
  },
  {
    input: "/atrium/a%20b",
    path: "/atrium/a%20b",
    root: "atrium",
    why: "an encoded space is fine; a raw one is not",
  },
  {
    input: "/newspapper/x/../y",
    path: "/newspapper/y",
    root: "newspapper",
    why: "traversal inside an allowed root collapses and stays inside it",
  },
  {
    input: "/atrium/..",
    path: "/",
    root: "",
    why: "traversal up to the apex is the apex, which is allowed",
  },
];

const REJECTED: ReadonlyArray<{ input: string | null | undefined; reason: NextRejection }> = [
  // ---- absent -------------------------------------------------------------
  { input: null, reason: "absent" },
  { input: undefined, reason: "absent" },
  { input: "", reason: "absent" },

  // ---- absolute URLs, the obvious attack ----------------------------------
  { input: "https://evil.example", reason: "not_absolute_path" },
  { input: "https://evil.example/atrium/", reason: "not_absolute_path" },
  { input: "http://evil.example", reason: "not_absolute_path" },
  { input: "HTTPS://EVIL.EXAMPLE", reason: "not_absolute_path" },
  // The estate's own origin spelled absolutely is still refused: this UI has no
  // business knowing what the origin is, and accepting one absolute host is how
  // a later edit accepts two.
  { input: "https://gandolh.ro/atrium/", reason: "not_absolute_path" },
  { input: "javascript:alert(1)", reason: "not_absolute_path" },
  { input: "data:text/html,<script>alert(1)</script>", reason: "not_absolute_path" },
  { input: "//evil.example", reason: "protocol_relative" },
  { input: "///evil.example", reason: "protocol_relative" },
  { input: "//evil.example/atrium/", reason: "protocol_relative" },

  // ---- backslash tricks ---------------------------------------------------
  { input: "\\\\evil.example", reason: "backslash" },
  { input: "/\\evil.example", reason: "backslash" },
  { input: "/\\/evil.example", reason: "backslash" },
  { input: "\\/\\/evil.example", reason: "backslash" },
  { input: "/atrium\\..\\..\\evil", reason: "backslash" },
  // Encoded, so the raw string is clean and the decoded one is not.
  { input: "/%5Cevil.example", reason: "backslash" },
  { input: "/%5c%5cevil.example", reason: "backslash" },
  // Double-encoded: `%255c` → `%5c` → `\`. Two passes.
  { input: "/%255Cevil.example", reason: "backslash" },

  // ---- whitespace and control characters ----------------------------------
  // A tab or newline is stripped by the URL parser, so `/\t/evil.example`
  // parses as `//evil.example` — the value means something different to the
  // parser than it does to a naive `startsWith("//")` check.
  { input: "/\t/evil.example", reason: "control_or_space" },
  { input: "/\n/evil.example", reason: "control_or_space" },
  { input: "/\r/evil.example", reason: "control_or_space" },
  { input: "\t//evil.example", reason: "control_or_space" },
  { input: " //evil.example", reason: "control_or_space" },
  { input: " /atrium/", reason: "control_or_space" },
  { input: "/atrium/ ", reason: "control_or_space" },
  { input: "/atrium/\u0000", reason: "control_or_space" },
  { input: "/atrium/\u007f", reason: "control_or_space" },
  { input: "/atrium/\u00a0evil", reason: "control_or_space" },
  { input: "/\u2028/evil.example", reason: "control_or_space" },
  { input: "/\ufeff/evil.example", reason: "control_or_space" },
  // Encoded whitespace, which is the form that actually turns up in a link.
  { input: "/%09//evil.example", reason: "control_or_space" },
  { input: "/%0a//evil.example", reason: "control_or_space" },
  { input: "/%00", reason: "control_or_space" },

  // ---- encoded slashes ----------------------------------------------------
  { input: "%2f%2fevil.example", reason: "not_absolute_path" },
  { input: "/%2f%2fevil.example", reason: "protocol_relative" },
  { input: "/%2F/evil.example", reason: "protocol_relative" },
  // `%252f` → `%2f` → `/`, so the decoded fixed point is `///evil.example`.
  { input: "/%252f%252fevil.example", reason: "protocol_relative" },

  // ---- malformed encoding -------------------------------------------------
  { input: "/atrium/%", reason: "undecodable" },
  { input: "/atrium/%zz", reason: "undecodable" },
  { input: "/atrium/%e0%a4%a", reason: "undecodable" },

  // ---- a path on this origin, but not an app ------------------------------
  { input: "/evil", reason: "unknown_root" },
  { input: "/atriumX/", reason: "unknown_root" },
  { input: "/atrium.evil.example/", reason: "unknown_root" },
  { input: "/Atrium/", reason: "unknown_root" },
  // Fullwidth Latin `a`. Renders like `atrium` and is not `atrium`.
  { input: "/ａtrium/", reason: "unknown_root" },
  { input: "/@evil.example", reason: "unknown_root" },
  // Traversal out of an allowed root, plain and percent-encoded. The encoded
  // form is the interesting one: the URL parser does not treat `%2e%2e` as a
  // dot segment, so only the decoded resolution catches it.
  { input: "/atrium/../../evil", reason: "unknown_root" },
  { input: "/atrium/%2e%2e/%2e%2e/evil", reason: "unknown_root" },
  { input: "/ward/../evil", reason: "unknown_root" },
  // The API roots are deliberately not estate paths: nobody was reading an
  // API endpoint, so `?next=` never legitimately names one.
  { input: "/atrium-api/auth/status", reason: "unknown_root" },
  { input: "/ward-api/introspect", reason: "unknown_root" },

  // ---- the loop -----------------------------------------------------------
  { input: "/ward/login", reason: "sign_in_loop" },
  { input: "/ward/login?next=/atrium/", reason: "sign_in_loop" },
  { input: "/ward/account/../login", reason: "sign_in_loop" },

  // ---- size ---------------------------------------------------------------
  { input: `/atrium/${"a".repeat(MAX_NEXT_LENGTH)}`, reason: "too_long" },
];

describe("resolveNext", () => {
  describe("accepts an estate path", () => {
    for (const row of ACCEPTED) {
      it(`${JSON.stringify(row.input)} — ${row.why}`, () => {
        const decision = resolveNext(row.input);
        expect(decision.accepted).toBe(true);
        expect(decision.path).toBe(row.path);
        if (decision.accepted) expect(decision.root).toBe(row.root);
      });
    }
  });

  describe("refuses everything else, and lands on the default", () => {
    for (const row of REJECTED) {
      it(`${JSON.stringify(row.input)} → ${row.reason}`, () => {
        const decision = resolveNext(row.input);
        expect(decision.accepted).toBe(false);
        // The visible behaviour, and the only part a person experiences: the
        // estate apex, silently. No error, no diagnostic, no partial redirect.
        expect(decision.path).toBe(DEFAULT_NEXT);
        if (!decision.accepted) expect(decision.reason).toBe(row.reason);
      });
    }
  });

  it("never returns anything but the default for a refusal", () => {
    // A property rather than a case: `path` is safe to use unconditionally, so
    // a caller that forgets to check `accepted` still cannot be redirected off
    // the origin. That is the invariant the type encodes and this asserts.
    for (const row of REJECTED) {
      expect(resolveNext(row.input).path).toBe(DEFAULT_NEXT);
    }
  });

  it("is idempotent over its own output", () => {
    // Whatever an accepted value normalises to must itself be accepted, or a
    // caller that round-trips the value through a URL loses the redirect.
    for (const row of ACCEPTED) {
      const once = resolveNext(row.input);
      expect(once.accepted).toBe(true);
      const twice = resolveNext(once.path);
      expect(twice.accepted).toBe(true);
      expect(twice.path).toBe(once.path);
    }
  });

  it("accepts a value of exactly the maximum length", () => {
    const filler = "a".repeat(MAX_NEXT_LENGTH - "/atrium/".length);
    const value = `/atrium/${filler}`;
    expect(value.length).toBe(MAX_NEXT_LENGTH);
    expect(resolveNext(value).accepted).toBe(true);
  });
});

describe("loginUrlFor", () => {
  it("encodes the destination so a query string survives", () => {
    // The mistake this exists to prevent: an unencoded `&` truncates `next` at
    // the first parameter, and the person lands on the app's home page instead
    // of the thing they clicked.
    const url = loginUrlFor("/prm/map?lat=45.7&lng=21.2");
    expect(url).toBe("/ward/login?next=%2Fprm%2Fmap%3Flat%3D45.7%26lng%3D21.2");
    const round = new URL(url, "https://ward.invalid").searchParams.get("next");
    expect(resolveNext(round)).toMatchObject({
      accepted: true,
      path: "/prm/map?lat=45.7&lng=21.2",
    });
  });
});
