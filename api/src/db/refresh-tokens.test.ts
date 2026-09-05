import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type Database from "better-sqlite3";
import { freshDb, seedUser } from "./test-support.js";
import {
  claimRefreshToken,
  deleteExpiredRefreshTokens,
  findRefreshToken,
  generateRefreshToken,
  hashRefreshToken,
  insertRefreshToken,
  listFamily,
  listLiveTokensForSubject,
  newFamilyId,
  revokeAllForSubject,
  revokeAllForSubjectExceptFamily,
  revokeFamily,
  revokeRefreshToken,
} from "./refresh-tokens.js";

let db: Database.Database;
let subject: string;

beforeEach(() => {
  db = freshDb();
  subject = seedUser(db, "alice").subject;
});

afterEach(() => {
  db.close();
});

const inThirtyDays = () => new Date(Date.now() + 30 * 86_400_000).toISOString();
const yesterday = () => new Date(Date.now() - 86_400_000).toISOString();

/** Mint a token the way brief 03 will: plaintext out, hash in. */
function mint(familyId: string, expiresAt = inThirtyDays()): { token: string; hash: string } {
  const token = generateRefreshToken();
  const hash = hashRefreshToken(token);
  insertRefreshToken(db, { tokenHash: hash, subject, familyId, expiresAt });
  return { token, hash };
}

describe("the token itself is never stored", () => {
  it("stores a hash, and the plaintext appears nowhere in the database", () => {
    const family = newFamilyId();
    const { token, hash } = mint(family);

    expect(token).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).not.toBe(token);

    const dump = JSON.stringify(db.prepare("SELECT * FROM refresh_tokens").all());
    expect(dump).not.toContain(token);
    expect(dump).toContain(hash);
  });

  it("hashing is deterministic, so presentation is an index seek", () => {
    const token = generateRefreshToken();
    expect(hashRefreshToken(token)).toBe(hashRefreshToken(token));
    expect(hashRefreshToken(token)).not.toBe(hashRefreshToken(generateRefreshToken()));
  });
});

describe("rotation", () => {
  it("a token can be spent exactly once", () => {
    const { hash } = mint(newFamilyId());

    expect(claimRefreshToken(db, hash)).toBeDefined();
    expect(claimRefreshToken(db, hash)).toBeUndefined();
    expect(findRefreshToken(db, hash)?.used_at).not.toBeNull();
  });

  it("refuses to spend an expired or already-revoked token", () => {
    const expired = mint(newFamilyId(), yesterday());
    expect(claimRefreshToken(db, expired.hash)).toBeUndefined();

    const revoked = mint(newFamilyId());
    revokeRefreshToken(db, revoked.hash, "logout");
    expect(claimRefreshToken(db, revoked.hash)).toBeUndefined();
  });

  it("carries the family through a rotation chain", () => {
    const family = newFamilyId();
    const first = mint(family);
    claimRefreshToken(db, first.hash);
    revokeRefreshToken(db, first.hash, "rotated");
    const second = mint(family);

    expect(listFamily(db, family).map((row) => row.token_hash)).toEqual([first.hash, second.hash]);
    expect(listFamily(db, family).every((row) => row.family_id === family)).toBe(true);
  });
});

describe("reuse detection kills the whole family in one write", () => {
  it("revokes every live descendant and leaves nothing usable", () => {
    const family = newFamilyId();
    const root = mint(family);
    const second = mint(family);
    const third = mint(family);
    const unrelated = mint(newFamilyId());

    // A replay of the already-spent root is the theft signal.
    claimRefreshToken(db, root.hash);
    expect(claimRefreshToken(db, root.hash)).toBeUndefined();

    const killed = revokeFamily(db, family, "reuse_detected");

    expect(killed).toBe(3);
    for (const member of [root, second, third]) {
      const row = findRefreshToken(db, member.hash);
      expect(row?.revoked_at).not.toBeNull();
      expect(row?.revoked_reason).toBe("reuse_detected");
      expect(claimRefreshToken(db, member.hash)).toBeUndefined();
    }

    // Another login's family is untouched.
    expect(findRefreshToken(db, unrelated.hash)?.revoked_at).toBeNull();
    expect(claimRefreshToken(db, unrelated.hash)).toBeDefined();
  });

  it("preserves the reason that killed a token first", () => {
    const family = newFamilyId();
    const rotated = mint(family);
    revokeRefreshToken(db, rotated.hash, "rotated");
    mint(family);

    expect(revokeFamily(db, family, "reuse_detected")).toBe(1);
    expect(findRefreshToken(db, rotated.hash)?.revoked_reason).toBe("rotated");
  });

  it("the schema refuses a revocation with no reason, or a reason with no revocation", () => {
    const { hash } = mint(newFamilyId());

    expect(() =>
      db.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ?").run("now", hash),
    ).toThrowError(/CHECK constraint failed/);

    expect(() =>
      db
        .prepare("UPDATE refresh_tokens SET revoked_reason = 'logout' WHERE token_hash = ?")
        .run(hash),
    ).toThrowError(/CHECK constraint failed/);
  });

  it("the schema refuses an unknown revocation reason", () => {
    const { hash } = mint(newFamilyId());

    expect(() =>
      db
        .prepare(
          "UPDATE refresh_tokens SET revoked_at = 'now', revoked_reason = ? WHERE token_hash = ?",
        )
        .run("because", hash),
    ).toThrowError(/CHECK constraint failed/);
  });
});

describe("account-wide operations", () => {
  it("signs out everywhere across every family", () => {
    mint(newFamilyId());
    mint(newFamilyId());
    mint(newFamilyId());

    expect(listLiveTokensForSubject(db, subject)).toHaveLength(3);
    expect(revokeAllForSubject(db, subject, "admin")).toBe(3);
    expect(listLiveTokensForSubject(db, subject)).toHaveLength(0);
  });

  /**
   * "Sign out my other devices" — the only self-serve response available to
   * somebody who suspects their session was stolen, because owner-issued
   * accounts have no verified email and therefore no recovery channel
   * (`corpus/wiki/decisions.md`). It is worthless if it signs the caller out
   * too, so the spared family is the assertion that matters.
   */
  describe("revoking every family but one", () => {
    it("leaves the spared family live and kills the rest", () => {
      const mine = newFamilyId();
      mint(mine);
      mint(newFamilyId());
      mint(newFamilyId());

      expect(revokeAllForSubjectExceptFamily(db, subject, mine, "logout")).toBe(2);

      const live = listLiveTokensForSubject(db, subject);
      expect(live).toHaveLength(1);
      expect(live[0]!.family_id).toBe(mine);
    });

    it("records the reason on the rows it killed and nothing on the one it spared", () => {
      const mine = newFamilyId();
      const theirs = newFamilyId();
      mint(mine);
      mint(theirs);

      revokeAllForSubjectExceptFamily(db, subject, mine, "logout");

      expect(listFamily(db, theirs).every((row) => row.revoked_reason === "logout")).toBe(true);
      expect(listFamily(db, mine).every((row) => row.revoked_at === null)).toBe(true);
    });

    it("spares every live row in the family, not just the newest", () => {
      // A raced refresh can leave two live rows in one family inside the grace
      // window. Both belong to the device being spared.
      const mine = newFamilyId();
      mint(mine);
      mint(mine);
      mint(newFamilyId());

      expect(revokeAllForSubjectExceptFamily(db, subject, mine, "logout")).toBe(1);
      expect(listLiveTokensForSubject(db, subject)).toHaveLength(2);
    });

    it("is a no-op when the spared family is the only one", () => {
      const mine = newFamilyId();
      mint(mine);

      expect(revokeAllForSubjectExceptFamily(db, subject, mine, "logout")).toBe(0);
      expect(listLiveTokensForSubject(db, subject)).toHaveLength(1);
    });

    it("never touches another account", () => {
      const bob = seedUser(db, "bob").subject;
      const bobToken = generateRefreshToken();
      insertRefreshToken(db, {
        tokenHash: hashRefreshToken(bobToken),
        subject: bob,
        familyId: newFamilyId(),
        expiresAt: inThirtyDays(),
      });

      mint(newFamilyId());
      revokeAllForSubjectExceptFamily(db, subject, "no-such-family", "logout");

      expect(listLiveTokensForSubject(db, bob)).toHaveLength(1);
    });

    it("leaves an already-dead row's original reason alone", () => {
      const doomed = newFamilyId();
      mint(doomed);
      revokeFamily(db, doomed, "reuse_detected");

      expect(revokeAllForSubjectExceptFamily(db, subject, newFamilyId(), "logout")).toBe(0);
      expect(listFamily(db, doomed)[0]!.revoked_reason).toBe("reuse_detected");
    });
  });

  it("live listing excludes expired rows even when they were never revoked", () => {
    mint(newFamilyId());
    mint(newFamilyId(), yesterday());

    expect(listLiveTokensForSubject(db, subject)).toHaveLength(1);
  });

  it("deleting the account takes its tokens with it", () => {
    mint(newFamilyId());
    db.prepare("DELETE FROM users WHERE subject = ?").run(subject);

    expect(db.prepare<[], number>("SELECT count(*) FROM refresh_tokens").pluck().get()).toBe(0);
  });

  it("refuses a token for an account that does not exist", () => {
    expect(() =>
      insertRefreshToken(db, {
        tokenHash: hashRefreshToken(generateRefreshToken()),
        subject: "nobody",
        familyId: newFamilyId(),
        expiresAt: inThirtyDays(),
      }),
    ).toThrowError(/FOREIGN KEY constraint failed/);
  });

  it("sweeps expired rows", () => {
    mint(newFamilyId());
    mint(newFamilyId(), yesterday());
    mint(newFamilyId(), yesterday());

    expect(deleteExpiredRefreshTokens(db)).toBe(2);
    expect(db.prepare<[], number>("SELECT count(*) FROM refresh_tokens").pluck().get()).toBe(1);
  });
});
