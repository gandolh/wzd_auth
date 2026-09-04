import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * The boot refusal, asserted rather than assumed: with no signing key on disk,
 * `buildApp()` rejects and Ward never gets as far as binding a port.
 *
 * This lives in its own file because it needs a process whose
 * `WARD_SIGNING_KEY_PATH` points at nothing — `config.ts` freezes the
 * environment at first import, and Vitest gives each test file its own worker
 * and module registry.
 *
 * The property under test is brief 02's last acceptance line, and the reason it
 * matters is in `tokens/keys.ts`: the alternative to refusing is generating a
 * key, and a key that appears on restart signs the whole estate out while
 * looking like an outage nobody caused.
 */

let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-jwks-boot-"));

  process.env["PORT"] = "8799";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "ward.db");
  process.env["WARD_ADMIN_USERNAME"] = "test-superuser";
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  // Deliberately absent. Nothing in this test creates it.
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = "https://gandolh.ro";
  // Mail is part of the required environment contract (brief 07). `file`
  // transport needs no SMTP credentials, which is the point of having a mode.
  process.env["WARD_MAIL_TRANSPORT"] = "file";
  process.env["WARD_MAIL_FILE_DIR"] = "api/mail-outbox";
  process.env["WARD_MAIL_FROM"] = "ward@gandolh.ro";
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("booting without a signing key", () => {
  it("refuses to build the app, and the error names the fix", async () => {
    const { buildApp } = await import("../app.js");

    await expect(buildApp()).rejects.toThrow(/npm run keygen/);
    await expect(buildApp()).rejects.toThrow(/signing key not found/);
  });
});
