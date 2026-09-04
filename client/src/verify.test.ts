import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createRemoteJwksKeyStore, jwksUrl, verifyAccessToken } from "./verify.js";
import { WardAuthenticationError } from "./errors.js";
import { startFakeWard, type FakeWard } from "./testing/fakeWard.js";

/**
 * Local, offline verification against a real EdDSA key pair and a real JWKS
 * endpoint over real HTTP — `startFakeWard` stands in for Ward's own
 * `GET /.well-known/jwks.json`, since this brief cannot run `api/` (brief 07
 * is editing it in parallel).
 *
 * The four rejection tests are the point of this file, mirroring
 * `api/src/tokens/tokens.test.ts`: a verifier that trusts the token's own
 * header passes every one of them.
 */

let ward: FakeWard;

beforeEach(async () => {
  ward = await startFakeWard();
});

afterEach(async () => {
  await ward.close();
});

describe("jwksUrl", () => {
  it("requires an explicit API base path and joins it correctly", () => {
    expect(jwksUrl("https://gandolh.ro", "/ward-api").toString()).toBe(
      "https://gandolh.ro/ward-api/.well-known/jwks.json",
    );
  });

  it("accepts an empty base path for a Ward served at its own root", () => {
    expect(jwksUrl("http://127.0.0.1:4000", "").toString()).toBe(
      "http://127.0.0.1:4000/.well-known/jwks.json",
    );
  });

  it("strips a trailing slash from the base path", () => {
    expect(jwksUrl("https://gandolh.ro", "/ward-api/").toString()).toBe(
      "https://gandolh.ro/ward-api/.well-known/jwks.json",
    );
  });
});

describe("verifyAccessToken", () => {
  it("verifies a token signed by a key in the published JWKS", async () => {
    const keyStore = createRemoteJwksKeyStore(ward.jwksEndpoint);
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });

    const claims = await verifyAccessToken(token, keyStore, { issuer: ward.origin });

    expect(claims.sub).toBe("sub_alice");
    expect(claims.sid).toBe("family_1");
    expect(claims.aud).toBe("ward-estate");
  });

  it("rejects a token signed by a key not in the JWKS", async () => {
    const otherWard = await startFakeWard();
    try {
      const keyStore = createRemoteJwksKeyStore(ward.jwksEndpoint);
      const foreignToken = await otherWard.mintToken({ issuer: ward.origin });

      await expect(
        verifyAccessToken(foreignToken, keyStore, { issuer: ward.origin }),
      ).rejects.toBeInstanceOf(WardAuthenticationError);
    } finally {
      await otherWard.close();
    }
  });

  it("rejects alg: none", async () => {
    const keyStore = createRemoteJwksKeyStore(ward.jwksEndpoint);
    const token = ward.mintUnsignedToken({ subject: "sub_alice" });

    await expect(
      verifyAccessToken(token, keyStore, { issuer: ward.origin }),
    ).rejects.toBeInstanceOf(WardAuthenticationError);
  });

  it("rejects alg: HS256 even with a header naming a real published kid", async () => {
    const keyStore = createRemoteJwksKeyStore(ward.jwksEndpoint);
    // `algorithms: ["EdDSA"]` is checked against the token's own header before
    // any key material is touched, so this does not need a genuinely valid
    // HMAC signature to prove the point — `jose` itself refuses to produce
    // one from Ed25519 key material in the first place, which is a form of
    // the same defence. Constructing the header/payload by hand simulates a
    // caller that got further than `jose`'s own signer would allow.
    const header = Buffer.from(JSON.stringify({ alg: "HS256", kid: "key-1", typ: "JWT" })).toString(
      "base64url",
    );
    const payload = Buffer.from(
      JSON.stringify({
        sub: "sub_alice",
        jti: "11111111-1111-4111-8111-111111111111",
        sid: "family_1",
        iss: ward.origin,
        aud: "ward-estate",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      }),
    ).toString("base64url");
    const forged = `${header}.${payload}.deadbeef`;

    await expect(
      verifyAccessToken(forged, keyStore, { issuer: ward.origin }),
    ).rejects.toBeInstanceOf(WardAuthenticationError);
  });

  it("rejects an expired token", async () => {
    const keyStore = createRemoteJwksKeyStore(ward.jwksEndpoint);
    const token = await ward.mintToken({ expiresInSeconds: -60 });

    await expect(
      verifyAccessToken(token, keyStore, { issuer: ward.origin }),
    ).rejects.toBeInstanceOf(WardAuthenticationError);
  });

  it("rejects a token missing the required sid claim", async () => {
    const keyStore = createRemoteJwksKeyStore(ward.jwksEndpoint);
    const token = await ward.mintToken({ includeSid: false });

    await expect(
      verifyAccessToken(token, keyStore, { issuer: ward.origin }),
    ).rejects.toBeInstanceOf(WardAuthenticationError);
  });

  it("picks up a rotated signing key without restarting the consumer", async () => {
    // cooldownDurationMs: 0 — see verify.ts's comment: in production a real
    // rotation is essentially always more than jose's 30-second cooldown
    // after the app's first request, but a test that mints the rotated
    // token in the same tick as the first fetch needs the floor removed to
    // observe the refetch happening immediately rather than after a real
    // 30-second wait.
    const keyStore = createRemoteJwksKeyStore(ward.jwksEndpoint, { cooldownDurationMs: 0 });

    // First verification populates jose's internal JWKS cache with only the
    // original key.
    const firstToken = await ward.mintToken({ subject: "sub_alice" });
    await verifyAccessToken(firstToken, keyStore, { issuer: ward.origin });

    // Rotate: a new key becomes current. The *same* keyStore object — no new
    // createRemoteJwksKeyStore call, standing in for "no restart".
    const newKid = await ward.rotateKey();
    const rotatedToken = await ward.mintToken({ subject: "sub_bob", kid: newKid });

    const claims = await verifyAccessToken(rotatedToken, keyStore, { issuer: ward.origin });
    expect(claims.sub).toBe("sub_bob");
  });
});
