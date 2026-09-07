import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import { SignJWT, exportJWK, generateKeyPair, type JWK, type KeyLike } from "jose";

/**
 * A minimal stand-in for Ward's own `GET /.well-known/jwks.json` and
 * `POST /introspect`, for tests that cannot run the real `api/` (brief 07 is
 * editing it in parallel) but must still exercise real HTTP, real EdDSA
 * signatures and real JSON over the wire — not mocked-out fetch calls.
 *
 * Not compiled into `dist/`: `client/tsconfig.json` excludes `src/testing/**`.
 * This is test infrastructure, not part of the published package.
 */

export interface FakeWardSession {
  active: boolean;
  subject: string;
  username: string;
  grants: Record<string, string[]>;
}

export interface MintTokenOptions {
  subject?: string;
  sessionId?: string;
  /** Which published key signs this token. Defaults to whichever is current. */
  kid?: string;
  issuer?: string;
  audience?: string;
  /** Override the header's `alg` — for negative tests only. */
  alg?: string;
  expiresInSeconds?: number;
  issuedAt?: Date;
  /** Omit the `sid` claim entirely — for negative tests only. Present by default. */
  includeSid?: boolean;
}

export interface FakeWard {
  readonly origin: string;
  readonly jwksEndpoint: URL;
  readonly introspectEndpoint: URL;
  readonly introspectCallCount: number;
  /** The `x-ward-app-key` header value seen on the most recent `/introspect` call, or `undefined` if none was sent. */
  readonly lastAppKey: string | undefined;
  /**
   * Require this exact app key on `/introspect`, answering `401
   * {"error":"invalid_app_key"}` to anything else — what the real Ward does.
   * Pass `undefined` to accept any key (the default, so existing tests that
   * care about caching and verification need not thread one through).
   */
  requireAppKey(key: string | undefined): void;
  mintToken(options?: MintTokenOptions): Promise<string>;
  /** An unsigned (`alg: "none"`) token — jose lets `SignJWT` produce this too, but building it by hand keeps the intent obvious. */
  mintUnsignedToken(options?: MintTokenOptions): string;
  setSession(sessionId: string, session: FakeWardSession | undefined): void;
  /** Force every subsequent `/introspect` call to answer with this HTTP status instead of the normal logic — `500` simulates "Ward is broken". Pass `undefined` to restore normal behaviour. */
  forceIntrospectStatus(status: number | undefined): void;
  /** Publish a new current signing key (the old one stays published too, exactly like Ward's current+previous JWKS). Returns the new key's `kid`. */
  rotateKey(): Promise<string>;
  close(): Promise<void>;
}

interface KeyEntry {
  kid: string;
  privateKey: KeyLike;
  publicJwk: JWK;
}

function base64url(input: object | string): string {
  const json = typeof input === "string" ? input : JSON.stringify(input);
  return Buffer.from(json).toString("base64url");
}

function decodeSid(token: string): string | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as {
      sid?: unknown;
    };
    return typeof payload.sid === "string" ? payload.sid : undefined;
  } catch {
    return undefined;
  }
}

export async function startFakeWard(): Promise<FakeWard> {
  const keys: KeyEntry[] = [];
  let currentKid = "";

  async function addKey(): Promise<string> {
    const kid = `key-${keys.length + 1}`;
    const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
      crv: "Ed25519",
      extractable: true,
    });
    const publicJwk = await exportJWK(publicKey);
    publicJwk.kid = kid;
    publicJwk.alg = "EdDSA";
    publicJwk.use = "sig";
    keys.push({ kid, privateKey, publicJwk });
    return kid;
  }

  currentKid = await addKey();

  const sessions = new Map<string, FakeWardSession>();
  let introspectCallCount = 0;
  let lastAppKey: string | undefined;
  let requiredAppKey: string | undefined;
  let forcedStatus: number | undefined;

  function currentKey(): KeyEntry {
    const key = keys.find((k) => k.kid === currentKid);
    if (!key) throw new Error("fakeWard: no current key");
    return key;
  }

  function keyByKid(kid: string): KeyEntry {
    const key = keys.find((k) => k.kid === kid);
    if (!key) throw new Error(`fakeWard: unknown kid ${kid}`);
    return key;
  }

  async function readBody(req: IncomingMessage): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    return Buffer.concat(chunks).toString("utf8");
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? "";

    if (req.method === "GET" && url === "/.well-known/jwks.json") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: keys.map((k) => k.publicJwk) }));
      return;
    }

    if (req.method === "POST" && url === "/introspect") {
      introspectCallCount += 1;

      const presented = req.headers["x-ward-app-key"];
      lastAppKey = typeof presented === "string" ? presented : undefined;

      // The real route checks this first, before the body or the token — so
      // this double does too, or a test could pass against an ordering the
      // service does not have.
      if (requiredAppKey !== undefined && lastAppKey !== requiredAppKey) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_app_key" }));
        return;
      }

      if (forcedStatus !== undefined) {
        res.writeHead(forcedStatus, { "content-type": "application/json" });
        res.end(forcedStatus === 200 ? JSON.stringify({ active: false }) : "server is broken");
        return;
      }

      let accessToken: string | undefined;
      try {
        const raw = await readBody(req);
        const parsed = raw.length > 0 ? (JSON.parse(raw) as { accessToken?: unknown }) : {};
        accessToken = typeof parsed.accessToken === "string" ? parsed.accessToken : undefined;
      } catch {
        accessToken = undefined;
      }

      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });

      const sid = accessToken ? decodeSid(accessToken) : undefined;
      const session = sid ? sessions.get(sid) : undefined;
      if (!session || !session.active) {
        res.end(JSON.stringify({ active: false }));
        return;
      }

      res.end(
        JSON.stringify({
          active: true,
          subject: session.subject,
          username: session.username,
          grants: session.grants,
        }),
      );
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  }

  const server: Server = createServer((req, res) => {
    handle(req, res).catch((error: unknown) => {
      res.writeHead(500);
      res.end(String(error));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  const origin = `http://127.0.0.1:${address.port}`;

  async function mintToken(options: MintTokenOptions = {}): Promise<string> {
    const key = options.kid ? keyByKid(options.kid) : currentKey();
    const now = options.issuedAt ?? new Date();
    const issuedAt = Math.floor(now.getTime() / 1000);
    const expiresAt = issuedAt + (options.expiresInSeconds ?? 900);

    const payload: Record<string, unknown> = {};
    if (options.includeSid !== false) {
      payload.sid = options.sessionId ?? "family_default";
    }

    return new SignJWT(payload)
      .setProtectedHeader({ alg: options.alg ?? "EdDSA", kid: key.kid, typ: "JWT" })
      .setSubject(options.subject ?? "sub_default")
      .setJti(randomUUID())
      .setIssuer(options.issuer ?? origin)
      .setAudience(options.audience ?? "ward-estate")
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(key.privateKey);
  }

  function mintUnsignedToken(options: MintTokenOptions = {}): string {
    const now = options.issuedAt ?? new Date();
    const issuedAt = Math.floor(now.getTime() / 1000);
    const expiresAt = issuedAt + (options.expiresInSeconds ?? 900);
    const header = { alg: "none", typ: "JWT" };
    const payload: Record<string, unknown> = {
      sub: options.subject ?? "sub_default",
      jti: randomUUID(),
      iss: options.issuer ?? origin,
      aud: options.audience ?? "ward-estate",
      iat: issuedAt,
      exp: expiresAt,
    };
    if (options.includeSid !== false) payload.sid = options.sessionId ?? "family_default";
    return `${base64url(header)}.${base64url(payload)}.`;
  }

  return {
    origin,
    jwksEndpoint: new URL("/.well-known/jwks.json", origin),
    introspectEndpoint: new URL("/introspect", origin),
    get lastAppKey() {
      return lastAppKey;
    },
    requireAppKey(key: string | undefined) {
      requiredAppKey = key;
    },
    get introspectCallCount() {
      return introspectCallCount;
    },
    mintToken,
    mintUnsignedToken,
    setSession(sessionId: string, session: FakeWardSession | undefined): void {
      if (session) sessions.set(sessionId, session);
      else sessions.delete(sessionId);
    },
    forceIntrospectStatus(status: number | undefined): void {
      forcedStatus = status;
    },
    async rotateKey(): Promise<string> {
      currentKid = await addKey();
      return currentKid;
    },
    async close(): Promise<void> {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}
