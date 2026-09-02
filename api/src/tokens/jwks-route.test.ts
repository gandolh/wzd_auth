import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import type { JSONWebKeySet } from "jose";

import { generateSigningKeyFile } from "./keygen.js";
import { createJwksKeyStore, verifyAccessToken } from "./verify.js";

/**
 * `GET /.well-known/jwks.json` through the real `buildApp()`, so the wiring is
 * under test and not just the helpers: registration, key loading at boot,
 * headers, and a token minted by the service verifying against the body the
 * route actually served.
 *
 * Every import of `../app.js` and `../config.js` here is **dynamic and inside
 * `beforeAll`**. `config.ts` validates the environment at import time and calls
 * `process.exit(1)` on anything missing — a static import would be hoisted
 * above the `process.env` assignments below and take the test worker with it.
 */

const ORIGIN = "https://gandolh.ro";

let dir: string;
let app: FastifyInstance;
let expectedKid: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-jwks-route-"));

  process.env["PORT"] = "8799";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "ward.db");
  process.env["WARD_ADMIN_USERNAME"] = "test-superuser";
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;

  // Ask config where it resolved the key path to, and write the key exactly
  // there — so this test cannot pass against a key the service would not load.
  const config = await import("../config.js");
  ({ kid: expectedKid } = await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH));

  const { buildApp } = await import("../app.js");
  app = await buildApp();
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  await rm(dir, { recursive: true, force: true });
});

describe("GET /.well-known/jwks.json", () => {
  it("serves a cacheable JWKS with the loaded key", async () => {
    const response = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });

    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/jwk-set+json");
    expect(response.headers["cache-control"]).toBe("public, max-age=300");

    const jwks = JSON.parse(response.body) as JSONWebKeySet;
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toEqual({
      kty: "OKP",
      crv: "Ed25519",
      x: expect.any(String),
      alg: "EdDSA",
      use: "sig",
      kid: expectedKid,
    });
  });

  it("never serves private key material", async () => {
    const response = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });

    // `d` is the parameter that would leak an Ed25519 private key. Checked on
    // the parsed key, and then on the raw bytes on the wire, because the second
    // one would also catch it appearing somewhere unexpected in the document.
    for (const jwk of (JSON.parse(response.body) as JSONWebKeySet).keys) {
      expect(jwk).not.toHaveProperty("d");
    }
    expect(response.body).not.toContain('"d"');
  });

  it("publishes the key a service-minted token can be verified with", async () => {
    // End to end: the service mints with the private half, the route publishes
    // the public half, and verification uses nothing but the served document.
    const { mintAccessToken } = await import("./service.js");
    const minted = await mintAccessToken("sub_route_test");

    const response = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    const store = createJwksKeyStore(JSON.parse(response.body) as JSONWebKeySet);

    const claims = await verifyAccessToken(minted.token, store, { issuer: ORIGIN });
    expect(claims.sub).toBe("sub_route_test");
    expect(claims.iss).toBe(ORIGIN);
    expect(minted.kid).toBe(expectedKid);
  });

  it("leaves the health route alone", async () => {
    const response = await app.inject({ method: "GET", url: "/health" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok" });
  });
});
