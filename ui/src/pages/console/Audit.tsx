/**
 * The audit log.
 *
 * ## Why this screen matters more than it looks like it should
 *
 * The break-glass credential cannot be revoked or rotated without a redeploy.
 * That is a deliberate trade — it is the only thing that still works when the
 * database is empty or the last admin has been removed — and the price of it is
 * that this log is the *only* observability the credential has. If something
 * was granted that should not have been, this is where it is found.
 *
 * ## `session.refresh_raced` versus `session.reuse_detected`
 *
 * These are the same event on the wire and opposite in meaning, and presenting
 * them alike destroys the signal. A race is two of the estate's tabs waking
 * together and refreshing at once — expected on a one-origin estate where six
 * apps share one access cookie — and nothing was revoked. A reuse is a replayed
 * token with no live successor: the stolen-cookie alarm, and the family was
 * burned down.
 *
 * `audit-actions.ts` holds that classification and it is unit-tested, because
 * the whole value of this screen is that the routine one does not bury the
 * alarm. The alarm is the only red row in the log.
 *
 * ## Paging is keyset, not offset
 *
 * `GET /console/audit` grows at the head, so an offset-paged second page
 * shifts under the reader every time anything happens elsewhere in the
 * estate. `nextBeforeId` in the response is the cursor for the next older
 * page, `null` when the page just fetched was the last one. Changing a filter
 * resets to the first page; the "Older" control moves forward through
 * `nextBeforeId`, and "Newer" pops back through a small stack of the cursors
 * already visited.
 */

import { useState } from "react";

import { consoleApi, type AuditQuery, type AuditRowView } from "../../console-api.js";
import { AUDIT_ACTION_GROUPS, parseGrantTarget, presentAuditAction } from "./audit-actions.js";
import { formatDetail, formatWhen, plural } from "./format.js";
import { useConsoleLoad } from "./session.js";
import { Alert, Empty, TextField } from "./ui.js";

/** The filter form's own state, all strings because that is what inputs hold. */
interface Draft {
  actorKind: string;
  actorLabel: string;
  actorSubject: string;
  targetKind: string;
  targetId: string;
  action: string;
}

const EMPTY: Draft = {
  actorKind: "",
  actorLabel: "",
  actorSubject: "",
  targetKind: "",
  targetId: "",
  action: "",
};

const ACTOR_KINDS = ["superuser", "account", "system"] as const;
type ActorKind = (typeof ACTOR_KINDS)[number];
function isActorKind(value: string): value is ActorKind {
  return (ACTOR_KINDS as readonly string[]).includes(value);
}

const TARGET_KINDS = ["user", "app", "grant", "session", "token"] as const;
type TargetKind = (typeof TARGET_KINDS)[number];
function isTargetKind(value: string): value is TargetKind {
  return (TARGET_KINDS as readonly string[]).includes(value);
}

/** The filters, without a page cursor — that is layered on separately below. */
function toFilters(draft: Draft): Omit<AuditQuery, "beforeId" | "limit"> {
  const query: Omit<AuditQuery, "beforeId" | "limit"> = {};
  if (draft.actorKind !== "" && isActorKind(draft.actorKind)) query.actorKind = draft.actorKind;
  if (draft.actorLabel !== "") query.actorLabel = draft.actorLabel;
  if (draft.actorSubject !== "") query.actorSubject = draft.actorSubject;
  if (draft.targetKind !== "" && isTargetKind(draft.targetKind))
    query.targetKind = draft.targetKind;
  if (draft.targetId !== "") query.targetId = draft.targetId;
  if (draft.action !== "") query.action = draft.action;
  return query;
}

export function AuditScreen(): React.JSX.Element {
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [filters, setFilters] = useState<Omit<AuditQuery, "beforeId" | "limit">>({});
  // Keyset pagination: a stack of cursors already visited. The first page has
  // no cursor at all, which is `undefined` here rather than a sentinel number
  // — `beforeId` genuinely starts at 1, so `0` or `-1` would be a real value
  // wearing a costume.
  const [cursors, setCursors] = useState<(number | undefined)[]>([undefined]);
  const cursor = cursors[cursors.length - 1];

  const query: AuditQuery = { ...filters, limit: 200, beforeId: cursor };
  const key = JSON.stringify(query);
  const { result } = useConsoleLoad(`audit:${key}`, () => consoleApi.listAudit(query));

  function applyFilters(next: Omit<AuditQuery, "beforeId" | "limit">): void {
    setFilters(next);
    setCursors([undefined]);
  }

  function older(): void {
    if (result.state !== "ready" || result.data.nextBeforeId === null) return;
    setCursors((stack) => [...stack, result.data.nextBeforeId ?? undefined]);
  }

  function newer(): void {
    setCursors((stack) => (stack.length > 1 ? stack.slice(0, -1) : stack));
  }

  const onFirstPage = cursors.length === 1;
  const hasOlder = result.state === "ready" && result.data.nextBeforeId !== null;

  return (
    <>
      <div className="wc-head">
        <h1>Audit log</h1>
      </div>

      <p className="wc-lede">
        Every change of authority in the estate, newest first, and every use of this console&rsquo;s
        credential. A no-op writes no row here — a duplicate grant, a second disable, a form
        resubmitted unchanged — deliberately, so that mis-clicks do not bury the rows that matter.
      </p>

      <form
        className="wc-form wc-form-row"
        onSubmit={(event) => {
          event.preventDefault();
          applyFilters(toFilters(draft));
        }}
      >
        <p className="wc-field">
          <label htmlFor="wc-audit-actor-kind">Actor kind</label>
          <select
            id="wc-audit-actor-kind"
            value={draft.actorKind}
            onChange={(event) => {
              setDraft({ ...draft, actorKind: event.target.value });
            }}
          >
            <option value="">Anyone</option>
            <option value="superuser">This console (superuser)</option>
            <option value="account">An ordinary account</option>
            <option value="system">Ward itself</option>
          </select>
        </p>
        <TextField
          label="Actor name"
          value={draft.actorLabel}
          onChange={(value) => {
            setDraft({ ...draft, actorLabel: value });
          }}
          autoComplete="off"
          spellCheck={false}
          opaque
          placeholder="cristian, or superuser"
        />
        <p className="wc-field">
          <label htmlFor="wc-audit-target-kind">Target kind</label>
          <select
            id="wc-audit-target-kind"
            value={draft.targetKind}
            onChange={(event) => {
              setDraft({ ...draft, targetKind: event.target.value });
            }}
          >
            <option value="">Anything</option>
            <option value="user">An account</option>
            <option value="app">An app</option>
            <option value="grant">A grant</option>
            <option value="session">A session</option>
            <option value="token">A token</option>
          </select>
        </p>
        <TextField
          label="Target"
          value={draft.targetId}
          onChange={(value) => {
            setDraft({ ...draft, targetId: value });
          }}
          autoComplete="off"
          spellCheck={false}
          opaque
          placeholder="a subject, or an app slug"
        />
        <p className="wc-field">
          <label htmlFor="wc-audit-action">Event</label>
          <select
            id="wc-audit-action"
            value={draft.action}
            onChange={(event) => {
              setDraft({ ...draft, action: event.target.value });
            }}
          >
            <option value="">Every event</option>
            {AUDIT_ACTION_GROUPS.map((group) => (
              <optgroup key={group.group} label={group.group}>
                {group.actions.map((action) => (
                  <option key={action} value={action}>
                    {presentAuditAction(action).label}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </p>
        <p className="wc-row-actions">
          <button type="submit" className="wc-btn" data-tone="primary">
            Filter
          </button>
          <button
            type="button"
            className="wc-btn"
            onClick={() => {
              setDraft(EMPTY);
              applyFilters({});
            }}
          >
            Clear
          </button>
        </p>
      </form>

      <p className="wc-lede">
        Actor name and target are matched exactly. An actor name is a username, or the literal{" "}
        <span className="wc-id">superuser</span> for anything done from this console — which is also
        why the actor filter offers a kind: a console mutation carries no subject to match on.
      </p>

      {result.state === "loading" ? <p className="wc-lede">Reading the log…</p> : null}

      {result.state === "failed" ? (
        <Alert tone="error" title="The log did not load" takeFocus>
          {result.message}
        </Alert>
      ) : null}

      {result.state === "ready" ? (
        result.data.entries.length === 0 ? (
          <Empty title="No matching events">
            <p>
              Nothing in the log matches those filters. An empty result is a real answer here — a
              no-op writes no row, so an action an operator attempted twice appears once.
            </p>
          </Empty>
        ) : (
          <AuditTable
            entries={result.data.entries}
            total={result.data.total}
            onFirstPage={onFirstPage}
            hasOlder={hasOlder}
            onOlder={older}
            onNewer={newer}
          />
        )
      ) : null}
    </>
  );
}

function AuditTable({
  entries,
  total,
  onFirstPage,
  hasOlder,
  onOlder,
  onNewer,
}: {
  entries: AuditRowView[];
  total: number;
  onFirstPage: boolean;
  hasOlder: boolean;
  onOlder: () => void;
  onNewer: () => void;
}): React.JSX.Element {
  const alarms = entries.filter((entry) => presentAuditAction(entry.action).isAlarm).length;

  return (
    <>
      {alarms > 0 ? (
        <Alert tone="error" title="Token replay in this window">
          {plural(alarms, "row", "rows")} record a refresh token presented after it was already
          spent, with no live successor in its family. That is the estate&rsquo;s stolen-cookie
          signal, not two tabs racing. Each family was revoked; rotate the affected account&rsquo;s
          password if you have not already.
        </Alert>
      ) : null}

      <div className="wc-table-scroll">
        <table className="wc-table">
          <caption>
            {plural(entries.length, "event", "events")} of {String(total)} in the log
            {onFirstPage ? "" : " (an older page)"}, newest first within the page.
          </caption>
          <thead>
            <tr>
              <th scope="col">When</th>
              <th scope="col">Event</th>
              <th scope="col">Actor</th>
              <th scope="col">Target</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <AuditRow key={entry.id} entry={entry} />
            ))}
          </tbody>
        </table>
      </div>

      <p className="wc-row-actions">
        <button type="button" className="wc-btn" disabled={onFirstPage} onClick={onNewer}>
          Newer
        </button>
        <button type="button" className="wc-btn" disabled={!hasOlder} onClick={onOlder}>
          Older
        </button>
      </p>
    </>
  );
}

function AuditRow({ entry }: { entry: AuditRowView }): React.JSX.Element {
  const presented = presentAuditAction(entry.action);
  const detail = formatDetail(entry.detail);
  const grant =
    entry.targetKind === "grant" && entry.targetId !== null
      ? parseGrantTarget(entry.targetId)
      : undefined;

  return (
    <tr className="wc-audit-row" data-severity={presented.severity}>
      <td className="wc-when">
        <time dateTime={entry.at} title={entry.at}>
          {formatWhen(entry.at)}
        </time>
      </td>
      <th scope="row">
        <span className="wc-audit-label">{presented.label}</span>
        <span className="wc-action">{entry.action}</span>
        {presented.explanation === "" ? null : (
          <p className="wc-audit-why">{presented.explanation}</p>
        )}
        {detail === "" ? null : <p className="wc-detail">{detail}</p>}
      </th>
      <td>
        {/* An actor label is a username, `superuser`, or a job name — never a
            link: the superuser has no account row to link to. */}
        <span className="wc-id">{entry.actorLabel}</span>
        {entry.actorSubject === null ? null : (
          <span className="wc-action">{entry.actorSubject}</span>
        )}
      </td>
      <td>
        {entry.targetId === null ? (
          <span className="wc-state" data-state="none">
            —
          </span>
        ) : grant === undefined ? (
          <span className="wc-id">{entry.targetId}</span>
        ) : (
          // A grant target is three percent-encoded parts joined by `:`,
          // because a role may itself contain a colon. Shown decoded.
          <span className="wc-id">
            {grant.subject} in {grant.appSlug} as {grant.role}
          </span>
        )}
      </td>
    </tr>
  );
}
