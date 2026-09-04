import type Database from "better-sqlite3";
import type { FastifyRequest } from "fastify";

import { getConsoleSession } from "./auth/console-guard.js";
import {
  recordAudit,
  SUPERUSER_LABEL,
  type ActorKind,
  type AuditLogRow,
  type TargetKind,
} from "./db/audit-log.js";

/**
 * The one place the console's admin routes turn "who is acting" into the three
 * actor columns of an `audit_log` row.
 *
 * `db/audit-log.ts` is the storage layer: it takes an `AuditEvent` with all of
 * `actorKind`, `actorSubject` and `actorLabel` spelled out, and it enforces the
 * CHECK that ties the first two together. This module is the layer above, and it
 * exists because those three fields are *not* a per-route decision:
 *
 *  - the console acts as `superuser` with a **null** `actor_subject`, because the
 *    break-glass credential has no `users` row to point at
 *    (`corpus/wiki/decisions-admin.md`);
 *  - inventing a sentinel subject to fill that column would be the rejected
 *    sentinel arriving through the audit log rather than through a JWT.
 *
 * Every route in brief 05 writes several kinds of event, and each one getting
 * those fields right independently is how a log ends up with two spellings of
 * the same actor. `consoleActor(request)` derives them once; `recordActorAudit`
 * applies them to an event.
 *
 * ## Why the actor is a value rather than a request
 *
 * `grants/write.ts` records its own audit rows **inside the transaction that
 * makes the change** — `db/audit-log.ts` is explicit that a change committed
 * outside its record's transaction leaves the log quietly disagreeing with the
 * data. That module must therefore be callable with no `FastifyRequest` at all
 * (a cutover script, a future job). So the actor travels as a plain `AuditActor`
 * struct, and only `consoleActor` knows about HTTP.
 */

/**
 * The actor half of an audit row, separated from the event half.
 *
 * Build it with `consoleActor` on the console surface. It is a plain value on
 * purpose: it crosses into `grants/write.ts`, which must stay free of Fastify.
 */
export interface AuditActor {
  actorKind: ActorKind;
  /** Non-null if and only if `actorKind` is `account` — a CHECK, not a style rule. */
  actorSubject?: string | null;
  actorLabel: string;
  /**
   * Context that belongs to the *actor* rather than to any one event, merged
   * under every event's `detail`. The console puts its session id here so the
   * log can say which sitting a change came from.
   *
   * A key here loses to the same key on an event's own `detail`: the event is
   * closer to what happened.
   */
  detail?: Record<string, unknown>;
}

/** The event half: what happened, and to what. */
export interface ActorAuditEvent {
  /** An opaque dotted verb — `app.create`, `grant.revoke`, `user.disable`. */
  action: string;
  targetKind?: TargetKind;
  /**
   * A subject, a slug, or — for a grant — `grantTargetId(...)`. **Never build a
   * grant's target id by hand**: role strings are opaque and may contain `:`, so
   * only the percent-encoding in `db/audit-log.ts` keeps two distinct triples
   * from encoding identically.
   */
  targetId?: string;
  detail?: Record<string, unknown>;
}

/**
 * The actor fields for a request that came through `requireConsoleSession`.
 *
 * `getConsoleSession` is the only thing this reads out of the session, and the
 * only thing there is to read: a console session carries an id, timestamps, and
 * deliberately no subject and no grants. The id is a non-secret handle — never
 * the token — so it is safe in a column the console itself renders.
 *
 * If the session is somehow absent (the guard did not run) the actor is still
 * `superuser`, just without a session id in `detail`. Losing the id is much
 * better than losing the row: nothing else in Ward records that authority
 * changed.
 */
export function consoleActor(request: FastifyRequest): AuditActor {
  const session = getConsoleSession(request);

  return {
    actorKind: "superuser",
    actorLabel: SUPERUSER_LABEL,
    detail: session === undefined ? {} : { session: session.id },
  };
}

/**
 * Append one event for a known actor.
 *
 * The `detail` written is the actor's context merged with the event's, and it is
 * omitted entirely when both are empty — `db/audit-log.ts` stores `null` rather
 * than `{}` so a reader can tell "no context" from "an empty object".
 */
export function recordActorAudit(
  db: Database.Database,
  actor: AuditActor,
  event: ActorAuditEvent,
): AuditLogRow {
  const detail = { ...actor.detail, ...event.detail };

  return recordAudit(db, {
    actorKind: actor.actorKind,
    actorSubject: actor.actorSubject ?? null,
    actorLabel: actor.actorLabel,
    action: event.action,
    targetKind: event.targetKind ?? null,
    targetId: event.targetId ?? null,
    detail: Object.keys(detail).length === 0 ? undefined : detail,
  });
}

/**
 * `recordActorAudit` with the actor derived from the request — the call every
 * console route makes when it is not handing the actor to `grants/write.ts`.
 */
export function recordConsoleAudit(
  db: Database.Database,
  request: FastifyRequest,
  event: ActorAuditEvent,
): AuditLogRow {
  return recordActorAudit(db, consoleActor(request), event);
}
