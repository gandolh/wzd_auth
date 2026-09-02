import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, rm, stat, writeFile, copyFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT, decodeProtectedHeader } from "jose";

import { ACCESS_TOKEN_ALG, ACCESS_TOKEN_AUDIENCE, ACCESS_TOKEN_TTL_SECONDS } from "./claims.js";
import { loadKeySet, previousSigningKeyPath, SigningKeyError } from "./keys.js";
import { signAccessToken } from "./mint.js";
import { createJwksKeyStore, verifyAccessToken, AccessTokenVerificationError } from "./verify.js";
import { generateSigningKeyFile } from "./keygen.js";
import type { WardKeySet } from "./keys.js";

/**
 * The token layer, tested against real Ed25519 material on a real (temporary)
 * disk — `keygen` writes the key, `loadKeySet` reads it, and the JWKS under
 * test is the same object the route serves.
 *
 * The four rejection tests below are the point of this file. Three of them —
 * the wrong key, `alg: "none"`, and the HMAC confusion — are attacks a verifier
 * that trusts the token's own header passes with flying colours, so a green
 * suite here is the evidence that Ward's verifier does not.
 */

const ISSUER = "https://gandolh.ro";

let dir: string;
let keySetA: WardKeySet;
let keySetB: WardKeySet;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-tokens-"));
  await generateSigningKeyFile(join(dir, "a.pem"));
  await generateSigningKeyFile(join(dir, "b.pem"));
  keySetA = await loadKeySet(join(dir, "a.pem"));
  keySetB = await loadKeySet(join(dir, "b.pem"));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

/** Mint a well-formed token with key A, the way `service.mintAccessToken` does. */
async function mint(subject = "sub_01H8XABCDEF", now?: Date) {
  return signAccessToken({ subject, signingKey: keySetA.current, issuer: ISSUER, now });
}

/** Compact-serialise an arbitrary header + payload with no signature at all. */
function unsignedJwt(header: object, payload: object): string {
  const part = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${part(header)}.${part(payload)}.`;
}

describe("the published JWKS", () => {
  it("carries no private key material", () => {
    for (const jwk of keySetA.jwks.keys) {
      // `d` is the field that would leak an Ed25519 private key. Asserted by
      // name because that is the one that matters, and then generically,
      // because a future key type would leak through a different letter.
      expect(jwk).not.toHaveProperty("d");
      expect(Object.keys(jwk).sort()).toEqual(["alg", "crv", "kid", "kty", "use", "x"]);
      expect(jwk.kty).toBe("OKP");
      expect(jwk.crv).toBe("Ed25519");
      expect(jwk.alg).toBe("EdDSA");
      expect(jwk.use).toBe("sig");
    }
  });

  it("names each key with a stable RFC 7638 thumbprint", async () => {
    const reloaded = await loadKeySet(join(dir, "a.pem"));
    // Same file, same kid — a restart must not change the name of a key that
    // tokens in flight already reference.
    expect(reloaded.current.kid).toBe(keySetA.current.kid);
    expect(keySetA.current.kid).not.toBe(keySetB.current.kid);
    expect(keySetA.current.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("publishes one key when no rotation is in progress", () => {
    expect(keySetA.jwks.keys).toHaveLength(1);
    expect(keySetA.previous).toBeUndefined();
  });
});

describe("minting", () => {
  it("sets exp to exactly 15 minutes after iat", async () => {
    const minted = await mint();
    expect(minted.expiresAt - minted.issuedAt).toBe(ACCESS_TOKEN_TTL_SECONDS);
    expect(ACCESS_TOKEN_TTL_SECONDS).toBe(900);
  });

  it("signs with EdDSA and names the key in the header", async () => {
    const header = decodeProtectedHeader((await mint()).token);
    expect(header.alg).toBe(ACCESS_TOKEN_ALG);
    expect(header.kid).toBe(keySetA.current.kid);
    expect(header.typ).toBe("JWT");
  });

  it("carries the subject, jti, iss and aud — and nothing about authority", async () => {
    const minted = await mint("sub_notarealsubject");
    const claims = await verifyAccessToken(minted.token, createJwksKeyStore(keySetA.jwks), {
      issuer: ISSUER,
    });
    expect(claims).toEqual({
      sub: "sub_notarealsubject",
      jti: minted.jti,
      iat: minted.issuedAt,
      exp: minted.expiresAt,
      iss: ISSUER,
      aud: ACCESS_TOKEN_AUDIENCE,
    });
    // decisions-tokens.md: permissions are NOT claims. A token minted before a
    // grant changed would carry stale authority for its whole lifetime.
    for (const forbidden of ["grants", "roles", "permissions", "scope", "admin"]) {
      expect(claims).not.toHaveProperty(forbidden);
    }
  });

  it("refuses to mint for an empty subject", async () => {
    await expect(
      signAccessToken({ subject: "  ", signingKey: keySetA.current, issuer: ISSUER }),
    ).rejects.toThrow(TypeError);
  });
});

describe("verification", () => {
  it("accepts a token against the JWKS that published its key", async () => {
    const minted = await mint();
    const claims = await verifyAccessToken(minted.token, createJwksKeyStore(keySetA.jwks), {
      issuer: ISSUER,
    });
    expect(claims.sub).toBe("sub_01H8XABCDEF");
  });

  it("rejects that same token against any other JWKS", async () => {
    // "verifies against the published JWKS and nothing else" — the other half.
    const minted = await mint();
    await expect(
      verifyAccessToken(minted.token, createJwksKeyStore(keySetB.jwks), { issuer: ISSUER }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });

  it("rejects a token signed with a different key", async () => {
    // Same claims, same algorithm, same shape — only the signing key differs.
    // A verifier that resolved the key from the token itself would accept this.
    const forged = await signAccessToken({
      subject: "sub_01H8XABCDEF",
      signingKey: keySetB.current,
      issuer: ISSUER,
    });
    await expect(
      verifyAccessToken(forged.token, createJwksKeyStore(keySetA.jwks), { issuer: ISSUER }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });

  it('rejects an unsigned token claiming alg: "none"', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = unsignedJwt(
      { alg: "none", typ: "JWT", kid: keySetA.current.kid },
      {
        sub: "sub_01H8XABCDEF",
        jti: "forged",
        iat: now,
        exp: now + ACCESS_TOKEN_TTL_SECONDS,
        iss: ISSUER,
        aud: ACCESS_TOKEN_AUDIENCE,
      },
    );
    await expect(
      verifyAccessToken(token, createJwksKeyStore(keySetA.jwks), { issuer: ISSUER }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });

  it("rejects an HS256 token signed with the public key's own bytes", async () => {
    // The classic algorithm-confusion attack. The public key is public, so if a
    // verifier lets the header choose a symmetric algorithm, the attacker's
    // "secret" is a value we hand out at /.well-known/jwks.json.
    const publicKeyBytes = Buffer.from(String(keySetA.current.publicJwk.x), "base64url");
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ jti: "forged" })
      .setProtectedHeader({ alg: "HS256", typ: "JWT", kid: keySetA.current.kid })
      .setSubject("sub_01H8XABCDEF")
      .setIssuer(ISSUER)
      .setAudience(ACCESS_TOKEN_AUDIENCE)
      .setIssuedAt(now)
      .setExpirationTime(now + ACCESS_TOKEN_TTL_SECONDS)
      .sign(new Uint8Array(publicKeyBytes));

    await expect(
      verifyAccessToken(token, createJwksKeyStore(keySetA.jwks), { issuer: ISSUER }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });

  it("rejects an expired token", async () => {
    const stale = await mint("sub_01H8XABCDEF", new Date(Date.now() - 20 * 60_000));
    await expect(
      verifyAccessToken(stale.token, createJwksKeyStore(keySetA.jwks), { issuer: ISSUER }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });

  it("rejects a token whose iss is not this Ward", async () => {
    const minted = await signAccessToken({
      subject: "sub_01H8XABCDEF",
      signingKey: keySetA.current,
      issuer: "https://evil.example",
    });
    await expect(
      verifyAccessToken(minted.token, createJwksKeyStore(keySetA.jwks), { issuer: ISSUER }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });

  it("rejects a token minted for a different audience", async () => {
    const minted = await signAccessToken({
      subject: "sub_01H8XABCDEF",
      signingKey: keySetA.current,
      issuer: ISSUER,
      audience: "some-other-estate",
    });
    await expect(
      verifyAccessToken(minted.token, createJwksKeyStore(keySetA.jwks), { issuer: ISSUER }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });

  it("rejects a token that omits exp entirely", async () => {
    const token = await new SignJWT({ jti: "no-exp" })
      .setProtectedHeader({ alg: ACCESS_TOKEN_ALG, typ: "JWT", kid: keySetA.current.kid })
      .setSubject("sub_01H8XABCDEF")
      .setIssuer(ISSUER)
      .setAudience(ACCESS_TOKEN_AUDIENCE)
      .setIssuedAt()
      .sign(keySetA.current.privateKey);
    await expect(
      verifyAccessToken(token, createJwksKeyStore(keySetA.jwks), { issuer: ISSUER }),
    ).rejects.toThrow(AccessTokenVerificationError);
  });
});

describe("key rotation", () => {
  it("publishes both keys and verifies tokens signed by either", async () => {
    // The rotation state: B is current (and signs), A is the outgoing key.
    await copyFile(join(dir, "a.pem"), previousSigningKeyPath(join(dir, "b.pem")));
    const rotating = await loadKeySet(join(dir, "b.pem"));

    expect(rotating.jwks.keys.map((k) => k.kid)).toEqual([
      keySetB.current.kid,
      keySetA.current.kid,
    ]);
    expect(rotating.current.kid).toBe(keySetB.current.kid);

    const store = createJwksKeyStore(rotating.jwks);
    const oldToken = await signAccessToken({
      subject: "sub_still_valid",
      signingKey: keySetA.current,
      issuer: ISSUER,
    });
    const newToken = await signAccessToken({
      subject: "sub_fresh",
      signingKey: rotating.current,
      issuer: ISSUER,
    });

    // Nobody is signed out by the rotation itself: that is the whole reason
    // the previous key stays published for one access-token lifetime.
    expect((await verifyAccessToken(oldToken.token, store, { issuer: ISSUER })).sub).toBe(
      "sub_still_valid",
    );
    expect((await verifyAccessToken(newToken.token, store, { issuer: ISSUER })).sub).toBe(
      "sub_fresh",
    );

    await rm(previousSigningKeyPath(join(dir, "b.pem")));
  });

  it("refuses to publish the same key twice", async () => {
    // `cp` where the procedure wanted `mv`. Two identical kids make every JWKS
    // lookup ambiguous, which would break verification estate-wide.
    const previous = previousSigningKeyPath(join(dir, "a.pem"));
    await copyFile(join(dir, "a.pem"), previous);
    await expect(loadKeySet(join(dir, "a.pem"))).rejects.toThrow(/same key as the current one/);
    await rm(previous);
  });

  it("derives the previous key's path from the current one", () => {
    expect(previousSigningKeyPath("/srv/ward/api/data/signing-key.pem")).toBe(
      "/srv/ward/api/data/signing-key.previous.pem",
    );
    expect(previousSigningKeyPath("/srv/ward/key")).toBe("/srv/ward/key.previous");
  });
});

describe("key loading refuses to guess", () => {
  it("fails loudly and names the fix when the key file is absent", async () => {
    const promise = loadKeySet(join(dir, "definitely-not-here.pem"));
    await expect(promise).rejects.toThrow(SigningKeyError);
    await expect(promise).rejects.toThrow(/npm run keygen/);
    await expect(promise).rejects.toThrow(/definitely-not-here\.pem/);
  });

  it("rejects a private key that is not Ed25519", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const path = join(dir, "rsa.pem");
    await writeFile(path, privateKey.export({ type: "pkcs8", format: "pem" }) as string);
    await expect(loadKeySet(path)).rejects.toThrow(/Ed25519 only/);
  });

  it("rejects a file that is not a key at all", async () => {
    const path = join(dir, "garbage.pem");
    await writeFile(path, "this is not a PEM\n");
    await expect(loadKeySet(path)).rejects.toThrow(/not a readable private key/);
  });
});

describe("keygen", () => {
  it("writes a 0600 key and refuses to overwrite it", async () => {
    const path = join(dir, "once.pem");
    const first = await generateSigningKeyFile(path);
    expect((await stat(path)).mode & 0o777).toBe(0o600);

    // Silently replacing a live signing key signs out every account in the
    // estate. The refusal is the filesystem's, via O_EXCL, not a check.
    await expect(generateSigningKeyFile(path)).rejects.toThrow(/refusing to overwrite/);
    await expect(generateSigningKeyFile(path)).rejects.toThrow(/npm run keygen/);

    const forced = await generateSigningKeyFile(path, { force: true });
    expect(forced.kid).not.toBe(first.kid);
  });
});
