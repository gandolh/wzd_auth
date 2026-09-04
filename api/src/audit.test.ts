import type Database from "better-sqlite3";
import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, expect, it } from "vitest";

import { consoleActor, recordActorAudit, recordConsoleAudit, type AuditActor } from "./audit.js";
import { requireConsoleSession } from "./auth/console-guard.js";
import {
  CONSOLE_COOKIE_NAME,
  openConsoleSession,
  resetConsoleSessionsForTests,
} from "./auth/superuser.js";
import { listAudit } from "./db/audit-log.js";
import { freshDb, seedUser } from "./db/test-support.js";

/**
 * The console's audit helper — the one place the three actor columns are
 * derived, so that no route hand-rolls them.
 *
 * `consoleActor` needs a real `FastifyRequest` that has been through the guard,
 * so the suite goes through a Fastify instance rather than faking one: the
 * session is attached to a module-private `WeakMap` keyed on the request object,
 * and a stub would be testing the stub.
 */

let db: Database.Database;
let app: FastifyInstance;
let cookie: string;
let sessionId: string;

beforeEach(async () => {
  db = freshDb();

  app = Fastify({ logger: false });
  app.post("/console/probe", { preHandler: requireConsoleSession }, async (request, reply) => {
    const body = request.body as { action: string; detail?: Record<string, unknown> };
    const row = recordConsoleAudit(db, request, {
      action: body.action,
      targetKind: "app",
      targetId: "atrium",
      detail: body.detail,
    });
    return reply.code(200).send({ id: row.id });
  });
  // Ungated on purpose: the guard has not run, so no session is attached.
  app.post("/console/ungated", async (request, reply) => {
    return reply.code(200).send({ actor: consoleActor(request) });
  });
  await app.ready();

  const opened = openConsoleSession();
  cookie = `${CONSOLE_COOKIE_NAME}=${encodeURIComponent(opened.token)}`;
  sessionId = opened.session.id;
});

afterEach(async () => {
  await app.close();
  db.close();
  resetConsoleSessionsForTests();
});

it("names the superuser with a null subject and the session in detail", async () => {
  const response = await app.inject({
    method: "POST",
    url: "/console/probe",
    payload: { action: "app.create" },
    headers: { cookie },
  });

  expect(response.statusCode).toBe(200);

  const [row] = listAudit(db);
  expect(row).toMatchObject({
    actor_kind: "superuser",
    /**
     * **Null, and it must stay null.** The break-glass credential has no `users`
     * row; a sentinel subject here would be the sentinel `decisions-admin.md`
     * rejected, arriving through the audit log rather than through a JWT. The
     * `audit_log` CHECK `(actor_subject IS NOT NULL) = (actor_kind = 'account')`
     * is the other half of the same rule.
     */
    actor_subject: null,
    actor_label: "superuser",
    action: "app.create",
    target_kind: "app",
    target_id: "atrium",
  });
  expect(JSON.parse(row!.detail!)).toEqual({ session: sessionId });
});

it("merges the actor's detail under the event's, and the event wins", async () => {
  await app.inject({
    method: "POST",
    url: "/console/probe",
    payload: { action: "app.update", detail: { name: "Atrium", session: "spoofed" } },
    headers: { cookie },
  });

  const [row] = listAudit(db);
  // The event is closer to what happened, so it wins the key — and this is
  // asserted rather than assumed because it is the only ordering that lets a
  // caller override context it knows better than the helper does.
  expect(JSON.parse(row!.detail!)).toEqual({ session: "spoofed", name: "Atrium" });
});

it("stores null rather than {} when there is no context at all", () => {
  const actor: AuditActor = { actorKind: "system", actorLabel: "sweep" };
  const row = recordActorAudit(db, actor, { action: "session.revoke" });

  // `null` and `{}` are different answers: "no context" against "an empty
  // object", and a reader of the log should be able to tell them apart.
  expect(row.detail).toBeNull();
});

it("keeps an account actor's subject, which the schema requires", () => {
  const user = seedUser(db, "cristian");
  const row = recordActorAudit(
    db,
    { actorKind: "account", actorSubject: user.subject, actorLabel: user.username },
    { action: "grant.create", targetKind: "user", targetId: user.subject },
  );

  expect(row.actor_kind).toBe("account");
  expect(row.actor_subject).toBe(user.subject);
});

it("still records an event when no session is attached, losing only the id", async () => {
  const response = await app.inject({ method: "POST", url: "/console/ungated" });

  // Losing the session id is much better than losing the row: nothing else in
  // Ward records that authority changed.
  expect(response.json().actor).toEqual({
    actorKind: "superuser",
    actorLabel: "superuser",
    detail: {},
  });
});
