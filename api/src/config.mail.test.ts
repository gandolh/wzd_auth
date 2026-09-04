import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * The mode-dependent half of the mail contract, exercised the only way it can
 * be: in a child process, because `config.ts` validates at import and exits.
 *
 * These assert the property brief 00 set for the whole file — a misconfigured
 * Ward fails at boot **naming the variable** — for a rule zod cannot express
 * per-field, since "required because another field says so" is cross-field.
 */
const HERE = resolve(fileURLToPath(import.meta.url), "..");
const REPO_ROOT = resolve(HERE, "..", "..");
const configPath = join(HERE, "config.ts");
const tsxCli = (() => {
  const candidate = join(REPO_ROOT, "node_modules", "tsx", "dist", "cli.mjs");
  return existsSync(candidate) ? candidate : undefined;
})();

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "ward-config-mail-"));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

function baseEnv(): Record<string, string> {
  return {
    PATH: process.env["PATH"] ?? "",
    PORT: "8799",
    HOST: "127.0.0.1",
    WARD_DB_PATH: join(dir, "child.db"),
    WARD_ADMIN_USERNAME: "root",
    WARD_ADMIN_PASSWORD: "break-glass",
    WARD_SIGNING_KEY_PATH: join(dir, "signing-key.pem"),
    WARD_PUBLIC_ORIGIN: "https://gandolh.ro",
    WARD_MAIL_FROM: "ward@gandolh.ro",
  };
}

async function importConfig(
  env: Record<string, string>,
): Promise<{ code: number; stderr: string }> {
  try {
    const { stderr } = await promisify(execFile)(process.execPath, [tsxCli!, configPath], {
      env,
      cwd: REPO_ROOT,
    });
    return { code: 0, stderr };
  } catch (error) {
    const failure = error as { code?: number; stderr?: string };
    return { code: failure.code ?? -1, stderr: failure.stderr ?? "" };
  }
}

describe("the mail transport is required, and each mode requires its own settings", () => {
  it.skipIf(tsxCli === undefined)("boots in file mode with a directory", async () => {
    const result = await importConfig({
      ...baseEnv(),
      WARD_MAIL_TRANSPORT: "file",
      WARD_MAIL_FILE_DIR: join(dir, "outbox"),
    });
    expect(result.code).toBe(0);
  });

  it.skipIf(tsxCli === undefined)("refuses file mode with no directory, naming it", async () => {
    const result = await importConfig({ ...baseEnv(), WARD_MAIL_TRANSPORT: "file" });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("WARD_MAIL_FILE_DIR");
  });

  it.skipIf(tsxCli === undefined)(
    "refuses smtp mode missing credentials, naming each",
    async () => {
      const result = await importConfig({
        ...baseEnv(),
        WARD_MAIL_TRANSPORT: "smtp",
        WARD_SMTP_HOST: "smtp.example.net",
      });
      expect(result.code).toBe(1);
      // The whole point of the cross-field check: it says which ones are missing.
      expect(result.stderr).toContain("WARD_SMTP_PORT");
      expect(result.stderr).toContain("WARD_SMTP_USER");
      expect(result.stderr).toContain("WARD_SMTP_PASSWORD");
      expect(result.stderr).not.toContain("WARD_SMTP_HOST:");
    },
  );

  it.skipIf(tsxCli === undefined)("boots in smtp mode with all four", async () => {
    const result = await importConfig({
      ...baseEnv(),
      WARD_MAIL_TRANSPORT: "smtp",
      WARD_SMTP_HOST: "smtp.example.net",
      WARD_SMTP_PORT: "587",
      WARD_SMTP_USER: "ward@gandolh.ro",
      WARD_SMTP_PASSWORD: "s3cret",
    });
    expect(result.code).toBe(0);
  });

  it.skipIf(tsxCli === undefined)("refuses an unknown transport", async () => {
    const result = await importConfig({ ...baseEnv(), WARD_MAIL_TRANSPORT: "sendgrid" });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("WARD_MAIL_TRANSPORT");
  });

  it.skipIf(tsxCli === undefined)("refuses a missing From address", async () => {
    const env: Record<string, string> = {
      ...baseEnv(),
      WARD_MAIL_TRANSPORT: "file",
      WARD_MAIL_FILE_DIR: join(dir, "o"),
    };
    delete env["WARD_MAIL_FROM"];
    const result = await importConfig(env);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("WARD_MAIL_FROM");
  });
});
