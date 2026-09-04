import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTransport } from "nodemailer";

import type { MailTransport } from "../config.js";

/**
 * The one place Ward sends mail from — `smtp` for real delivery, `file` for a
 * rehearsal written to disk.
 *
 * ## Why the mode is a parameter and not an `if (NODE_ENV)`
 *
 * `config.ts` exports `MAIL` as a **discriminated union** and requires
 * `WARD_MAIL_TRANSPORT` explicitly, because the obvious way to satisfy brief
 * 07's "development needs no SMTP credentials" — sniff the environment and fall
 * back to files — is the silent default that whole file exists to refuse. An
 * estate whose mail stopped leaving the building because a variable was unset
 * somewhere is a registration flow that appears to work and delivers nothing.
 * Nothing here re-derives the mode; it is read from the union or handed in.
 *
 * ## Why `file` mode goes through nodemailer too
 *
 * The naive `file` transport writes `To: …\nSubject: …\n\n<body>` by hand, and
 * the moment it does, the file stops being evidence about what SMTP would send:
 * no `From:`, no `Date:`, no `Message-ID:`, no MIME headers, no quoted-printable
 * encoding, and no way to notice that the real path is broken until the day
 * somebody switches to `smtp`. So `file` mode uses nodemailer's
 * **stream transport**, which runs the same MIME builder the SMTP transport
 * runs and hands back the exact bytes that would have gone on the wire. What
 * lands in `MAIL.dir` is a `.eml` file any mail client will open.
 *
 * ## What must never reach the log
 *
 * A verification mail holds a **single-use token**, which is why `MAIL.dir` is
 * gitignored — those files are credentials on disk, not logs. `public-resource-map`
 * logs the whole link to stdout in its dev mailer; Ward deliberately does not,
 * because Ward's log is a real log that gets tailed, shipped and kept. Nothing
 * in this module logs anything at all: it returns the path it wrote and lets the
 * caller decide what is safe to say about it.
 */

/** A message to send. Plain text only — see `templates.ts` for why. */
export interface OutgoingMail {
  to: string;
  subject: string;
  text: string;
}

/**
 * What was done with a message.
 *
 * `path` exists only on the `file` branch, and it is the one thing about a
 * verification mail that is safe to log: it names a file rather than carrying
 * the token inside it.
 */
export type SentMail =
  { kind: "file"; messageId: string; path: string } | { kind: "smtp"; messageId: string };

/**
 * Send `message` over `transport`, or over the process-wide `MAIL` when no
 * transport is given.
 *
 * The transport is a **parameter with a lazy default**, exactly like the `db`
 * option on every route plugin, and for the same reason: `import("../config.js")`
 * is dynamic so that merely importing this module never runs config's
 * validation (and its `process.exit(1)`). A test can hand in
 * `{ kind: "file", dir, from }` and exercise the whole path with no environment
 * set at all.
 *
 * Throws whatever the transport throws — an unreachable SMTP host, an
 * unwritable directory. The caller decides what that means; for
 * `POST /register` it means the account still exists and the answer says the
 * mail did not go, because the alternative is a `500` for a registration that
 * actually succeeded and a username that is now taken.
 */
export async function sendMail(
  message: OutgoingMail,
  transport?: MailTransport,
): Promise<SentMail> {
  const target = transport ?? (await import("../config.js")).MAIL;

  /**
   * Header fields are scrubbed of control characters before they reach the MIME
   * builder. `to` is anonymous input on the registration path, and a `\r\n` in
   * a header value is how a submitted address turns into an extra `Bcc:`.
   * zod's email format already refuses one, `from` and `subject` are
   * operator-controlled, and nodemailer encodes headers itself — this is the
   * third of three, because header injection is cheap to prevent and expensive
   * to discover.
   */
  const envelope = {
    from: headerSafe(target.from),
    to: headerSafe(message.to),
    subject: headerSafe(message.subject),
    text: message.text,
  };

  if (target.kind === "file") {
    return writeToOutbox(target.dir, envelope);
  }
  return sendOverSmtp(target, envelope);
}

type Envelope = OutgoingMail & { from: string };

/**
 * Build the message with nodemailer's stream transport and write the bytes.
 *
 * `newline: "unix"` so the file reads the same on the machine it was written
 * on; SMTP itself is CRLF and the SMTP transport handles that, which is a
 * difference between the two modes and the only one.
 */
async function writeToOutbox(dir: string, envelope: Envelope): Promise<SentMail> {
  const mailer = createTransport({ streamTransport: true, buffer: true, newline: "unix" });
  const info = await mailer.sendMail(envelope);

  if (!Buffer.isBuffer(info.message)) {
    // Unreachable with `buffer: true`, and an assertion rather than a stream
    // fallback on purpose: a silent second code path here is a second thing to
    // keep correct, and nodemailer's own contract says which one it returns.
    throw new Error("nodemailer stream transport returned a stream despite buffer: true");
  }

  /**
   * `0o700` on the directory and `0o600` on the file, because each message
   * holds a live single-use token. The default umask would leave these
   * world-readable, which on a VPS shared with six apps means any process can
   * read a verification link out of the outbox and take over the account it was
   * mailed to.
   */
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, outboxFilename());
  await writeFile(path, info.message, { mode: 0o600 });

  return { kind: "file", messageId: info.messageId, path };
}

/**
 * Real delivery.
 *
 * A fresh transporter per message rather than a memoised one. nodemailer
 * without `pool: true` opens a connection per send anyway, so memoising saves
 * an object allocation and nothing else — and it would make `sendMail`
 * behave differently for the second call with a different injected transport,
 * which is precisely the kind of hidden state a test cannot see.
 *
 * `secure` is implicit TLS, which is port 465 and only port 465. On 587 (and
 * anything else) the connection starts in the clear and upgrades, so
 * `requireTLS` is set to make that upgrade **mandatory** — without it
 * nodemailer will happily fall back to plaintext when a server does not offer
 * STARTTLS, and `WARD_SMTP_PASSWORD` goes across the network in the open.
 */
async function sendOverSmtp(
  target: Extract<MailTransport, { kind: "smtp" }>,
  envelope: Envelope,
): Promise<SentMail> {
  const secure = target.port === 465;
  const mailer = createTransport({
    host: target.host,
    port: target.port,
    secure,
    requireTLS: !secure,
    auth: { user: target.user, pass: target.password },
  });

  const info = await mailer.sendMail(envelope);
  return { kind: "smtp", messageId: info.messageId };
}

/**
 * A sortable, non-colliding filename.
 *
 * The timestamp first so `ls` orders the outbox chronologically, `:` and `.`
 * replaced because they are awkward-to-hostile in filenames, and four random
 * bytes because two registrations in the same millisecond must not overwrite
 * each other. **The recipient is deliberately not in the name** — a directory
 * listing should not be a list of who signed up.
 */
function outboxFilename(): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `${stamp}-${randomBytes(4).toString("hex")}.eml`;
}

/**
 * Strip everything that could end a header line or hide inside one: CR, LF,
 * and the rest of the C0/C1 control ranges. Surrounding space goes too, since a
 * trailing space in an address is invisible and never meant.
 */
function headerSafe(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").trim();
}
