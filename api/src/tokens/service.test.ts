import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { generateSigningKeyFile } from "./keygen.js";
import { signAccessToken } from "./mint.js";
import { AccessTokenVerificationError } from "./verify.js";
import { newFamilyId } from "../db/refresh-tokens.js";
import type { AccessTokenClaims } from "./claims.js";
import type { WardKeySet } from "./keys.js";

/**
 * `verifyWardAccessToken` — the trust-critical entry point, and the assertion
 * that a caller cannot weaken it.
 *
 * It used to take a `Partial<VerifyAccessTokenOptions>` that was spread *after*
 * the pinned issuer, so any call site could extend a token's lifetime without
 * bound, accept any issuer, accept any audience, or move the clock — all of it
 * type-checking cleanly. Brief 04's `/introspect` is the caller that matters
 * and brief 08 re-exports this surface into six apps, so the failure mode was
 * one line of well-meaning skew-chasing making every expired or stolen token in
 * the estate introspect as authentic, with nothing going red.
 *
 * The fix is structural: the function takes a token and nothing else. Both
 * halves of that are tested here — the compile-time half with
 * `@ts-expect-error`, and the runtime half by forcing the old signature past the
 * compiler through `unknown`, because a guarantee that lives only in the type
 * checker is a guarantee a `JSON.parse` result can walk around.
 *
 * This file sets `process.env` itself and imports `service.js` dynamically:
 * `config.ts` validates the environment at import time and calls
 * `process.exit(1)` on anything missing, and Vitest gives each test file its own
 * worker and module registry.
 */

const ORIGIN = "https://gandolh.ro";

let dir: string;
let keySet: WardKeySet;
let verifyWardAccessToken: (token: string) => Promise<AccessTokenClaims>;

/**
 * The signature the entry point used to have, forced past the compiler on
 * purpose. Everything a call site could once have said, it may still *say* —
 * this type exists to prove that saying it changes nothing.
 */
type WithOverrides = (token: string, overrides?: Record<string, unknown>) => Promise<unknown>;
let forced: WithOverrides;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-service-verify-"));

  process.env["PORT"] = "8799";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "ward.db");
  process.env["WARD_ADMIN_USERNAME"] = "test-superuser";
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;

  const config = await import("../config.js");
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  const service = await import("./service.js");
  verifyWardAccessToken = service.verifyWardAccessToken;
  forced = service.verifyWardAccessToken as unknown as WithOverrides;
  keySet = await service.getKeySet();
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

/** A token signed by Ward's own key, with whatever claims the case needs. */
async function wardSigned(params: {
  subject?: string;
  issuer?: string;
  audience?: string;
  now?: Date;
}) {
  return signAccessToken({
    subject: params.subject ?? "sub_01H8XABCDEF",
    sessionId: newFamilyId(),
    signingKey: keySet.current,
    issuer: params.issuer ?? ORIGIN,
    ...(params.audience === undefined ? {} : { audience: params.audience }),
    ...(params.now === undefined ? {} : { now: params.now }),
  });
}

describe("verifyWardAccessToken pins every claim itself", () => {
  it("accepts a token Ward just minted", async () => {
    const { mintAccessToken } = await import("./service.js");
    const minted = await mintAccessToken("sub_live", newFamilyId());

    const claims = await verifyWardAccessToken(minted.token);
    expect(claims.sub).toBe("sub_live");
    expect(claims.iss).toBe(ORIGIN);
  });

  it("takes no options argument at all", async () => {
    // The compile-time half. If a second argument ever type-checks again, this
    // directive becomes an unused-`@ts-expect-error` error and `npm run
    // typecheck` fails — which is the point: the hole cannot come back quietly.
    const { mintAccessToken } = await import("./service.js");
    const minted = await mintAccessToken("sub_live", newFamilyId());
    // @ts-expect-error verifyWardAccessToken takes a token and nothing else.
    const claims = await verifyWardAccessToken(minted.token, { clockToleranceSeconds: 5 });
    // And at runtime the extra argument is simply not read.
    expect(claims.sub).toBe("sub_live");
  });

  it("cannot be made to extend a token's lifetime", async () => {
    // Expired 30 days ago. `jose` compares `exp <= now - tolerance`, so a large
    // `clockToleranceSeconds` is not a skew allowance, it is a lifetime.
    const stale = await wardSigned({ now: new Date(Date.now() - 30 * 86_400_000) });

    await expect(verifyWardAccessToken(stale.token)).rejects.toThrow(AccessTokenVerificationError);
    await expect(forced(stale.token, { clockToleranceSeconds: 60 * 86_400 })).rejects.toThrow(
      AccessTokenVerificationError,
    );
  });

  it("cannot be made to accept a foreign issuer", async () => {
    // Signed by Ward's real key — only `iss` is wrong. `requiredClaims` forces
    // presence, not value, so an unpinned issuer accepts this happily.
    const foreign = await wardSigned({ issuer: "https://evil.example" });

    await expect(verifyWardAccessToken(foreign.token)).rejects.toThrow(
      AccessTokenVerificationError,
    );
    for (const overrides of [
      { issuer: undefined },
      { issuer: "https://evil.example" },
      { issuer: null },
    ]) {
      await expect(forced(foreign.token, overrides)).rejects.toThrow(AccessTokenVerificationError);
    }
  });

  it("cannot be made to accept a foreign audience", async () => {
    const foreign = await wardSigned({ audience: "some-other-estate" });

    await expect(verifyWardAccessToken(foreign.token)).rejects.toThrow(
      AccessTokenVerificationError,
    );
    for (const overrides of [{ audience: "some-other-estate" }, { audience: undefined }]) {
      await expect(forced(foreign.token, overrides)).rejects.toThrow(AccessTokenVerificationError);
    }
  });

  it("cannot be made to backdate the clock", async () => {
    const stale = await wardSigned({ now: new Date(Date.now() - 30 * 86_400_000) });

    await expect(
      forced(stale.token, { currentDate: new Date(Date.now() - 30 * 86_400_000) }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });

  it("ignores an override even when every dangerous field is set at once", async () => {
    // The realistic shape of the bug: a settings object arriving from somewhere
    // else entirely and being handed straight through.
    const stale = await wardSigned({
      issuer: "https://evil.example",
      audience: "some-other-estate",
      now: new Date(Date.now() - 30 * 86_400_000),
    });

    await expect(
      forced(stale.token, {
        issuer: undefined,
        audience: "some-other-estate",
        clockToleranceSeconds: 365 * 86_400,
        currentDate: new Date(Date.now() - 30 * 86_400_000),
      }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });
});
