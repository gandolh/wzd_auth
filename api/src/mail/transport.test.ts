import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { MailTransport } from "../config.js";
import { sendMail } from "./transport.js";

/**
 * The `file` transport, end to end, with **no environment set at all**.
 *
 * That is the whole point of `sendMail` taking the transport as a parameter:
 * these tests never import `config.ts`, never set `WARD_MAIL_*`, and therefore
 * cannot be the reason a config change breaks the suite. The route-level test
 * (`routes/register.test.ts`) exercises the other half — that the process-wide
 * `MAIL` reaches this function when nothing is passed.
 *
 * The `smtp` branch is deliberately not tested here: asserting it would mean
 * either a live SMTP server in CI or a mock of nodemailer, and a mock of the
 * library would test the mock. What is asserted instead is that `file` mode
 * produces a **real RFC 5322 message** — the same MIME builder the SMTP
 * transport runs — so the thing that would differ between the two modes is the
 * connection, not the message.
 */

let dir: string;

/**
 * A `file` transport pointed at `target`.
 *
 * Annotated as `MailTransport` rather than spread from a shared object literal:
 * spreading a discriminated union and overriding one member's field is not
 * assignable to the union, and the compiler is right to say so.
 */
const fileTransport = (target: string): MailTransport => ({
  kind: "file",
  dir: target,
  from: "Ward <ward@gandolh.ro>",
});

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-mail-transport-"));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function onlyMessage(subdir: string): Promise<{ path: string; body: string }> {
  const files = await readdir(subdir);
  expect(files).toHaveLength(1);
  const path = join(subdir, files[0]!);
  return { path, body: await readFile(path, "utf8") };
}

describe("file transport", () => {
  it("writes a real message, headers and all, including the From:", async () => {
    const target = join(dir, "outbox-basic");
    const result = await sendMail(
      { to: "alice@example.com", subject: "Confirm your email address", text: "a link\n" },
      fileTransport(target),
    );

    expect(result.kind).toBe("file");
    const { body } = await onlyMessage(target);

    /**
     * The acceptance criterion for `file` mode is that it is a **rehearsal** of
     * what SMTP would send. A hand-rolled writer produces none of these, and
     * the day somebody switches to `smtp` is the day they find out.
     */
    expect(body).toContain("From: Ward <ward@gandolh.ro>");
    expect(body).toContain("To: alice@example.com");
    expect(body).toContain("Subject: Confirm your email address");
    expect(body).toMatch(/^Date: .+$/m);
    expect(body).toMatch(/^Message-ID: <.+>$/m);
    expect(body).toContain("MIME-Version: 1.0");
    expect(body).toContain("Content-Type: text/plain");
    // Headers, a blank line, then the body — the shape of an actual message.
    expect(body).toMatch(/\n\na link/);
  });

  it("creates the outbox and keeps the message readable only by its owner", async () => {
    const target = join(dir, "nested", "outbox");
    const result = await sendMail(
      { to: "alice@example.com", subject: "s", text: "t" },
      fileTransport(target),
    );

    /**
     * A verification mail holds a live single-use token, so these files are
     * credentials on disk. The default umask would leave them world-readable,
     * and on a VPS shared with six apps that is an account takeover for anyone
     * who can run `cat`.
     */
    const mode = (await stat(result.kind === "file" ? result.path : "")).mode & 0o777;
    expect(mode).toBe(0o600);
    expect((await stat(target)).mode & 0o777).toBe(0o700);
  });

  it("names files by time and randomness, never by recipient", async () => {
    const target = join(dir, "outbox-names");
    await sendMail({ to: "alice@example.com", subject: "s", text: "t" }, fileTransport(target));
    await sendMail({ to: "bob@example.com", subject: "s", text: "t" }, fileTransport(target));

    const files = await readdir(target);
    expect(files).toHaveLength(2);
    for (const name of files) {
      expect(name.endsWith(".eml")).toBe(true);
      // A directory listing must not be a list of who signed up.
      expect(name).not.toContain("alice");
      expect(name).not.toContain("bob");
    }
  });

  it("strips control characters out of header values", async () => {
    const target = join(dir, "outbox-injection");
    await sendMail(
      {
        // The shape of a header-injection attempt: a submitted address that
        // tries to end its own line and start a Bcc.
        to: "alice@example.com\r\nBcc: attacker@example.net",
        subject: "line one\nline two",
        text: "t",
      },
      fileTransport(target),
    );

    const { body } = await onlyMessage(target);
    // No injected header of its own: whatever the mangled address becomes, it
    // stays inside the `To:` value rather than becoming a line.
    expect(body).not.toMatch(/^Bcc:/m);
    expect(body).toMatch(/^Subject: line oneline two$/m);
  });
});
