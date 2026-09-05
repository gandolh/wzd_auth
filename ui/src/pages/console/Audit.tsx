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
 * ## The endpoint does not exist yet
 *
 * There is no `GET /console/audit` in the API. Everything behind it does exist —
 * `api/src/db/audit-log.ts` already has `listAudit`, `countAudit` and keyset
 * pagination — so what is missing is a route behind the console guard, plus two
 * fields on its query. Rather than ship a screen that shows an empty log and
 * looks like a quiet estate, this says precisely what is missing and what it
 * would take. Everything else here is finished and starts working the moment
 * the route lands.
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

function toQuery(draft: Draft): AuditQuery {
  const query: AuditQuery = { limit: 200 };
  if (draft.actorKind !== "") query.actorKind = draft.actorKind;
  if (draft.actorLabel !== "") query.actorLabel = draft.actorLabel;
  if (draft.actorSubject !== "") query.actorSubject = draft.actorSubject;
  if (draft.targetKind !== "") query.targetKind = draft.targetKind;
  if (draft.targetId !== "") query.targetId = draft.targetId;
  if (draft.action !== "") query.action = draft.action;
  return query;
}

export function AuditScreen(): React.JSX.Element {
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [applied, setApplied] = useState<AuditQuery>({ limit: 200 });
  const key = JSON.stringify(applied);
  const { result } = useConsoleLoad(`audit:${key}`, () => consoleApi.listAudit(applied));

  // `not_found` from this path means the route itself is absent: there is no
  // row-level 404 on a listing. See `MissingEndpoint` below.
  const missing = result.state === "failed" && result.code === "not_found";

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
          setApplied(toQuery(draft));
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
              setApplied({ limit: 200 });
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

      {missing ? <MissingEndpoint /> : null}

      {result.state === "loading" ? <p className="wc-lede">Reading the log…</p> : null}

      {result.state === "failed" && !missing ? (
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
          <AuditTable entries={result.data.entries} total={result.data.total} />
        )
      ) : null}
    </>
  );
}

/**
 * Said out loud rather than hidden behind an empty table.
 *
 * An audit screen that shows nothing looks like an estate where nothing has
 * happened, which is the single most misleading thing this console could tell
 * an operator who came here because something did.
 */
function MissingEndpoint(): React.JSX.Element {
  return (
    <Alert tone="notice" title="Ward does not serve the audit log yet" takeFocus>
      The API has no <span className="wc-id">GET /console/audit</span>. This screen — the filters,
      the ordering and the treatment that keeps{" "}
      <span className="wc-id">session.reuse_detected</span> distinct from{" "}
      <span className="wc-id">session.refresh_raced</span> — is finished and will populate the
      moment that route exists. What it needs: a handler behind{" "}
      <span className="wc-id">requireConsoleSession</span> that calls the existing{" "}
      <span className="wc-id">listAudit</span> / <span className="wc-id">countAudit</span> in{" "}
      <span className="wc-id">api/src/db/audit-log.ts</span>, camel-cases the row and parses{" "}
      <span className="wc-id">detail</span>, plus <span className="wc-id">actorKind</span> and{" "}
      <span className="wc-id">actorLabel</span> added to <span className="wc-id">AuditQuery</span> —
      without those two, every console mutation is unfilterable by actor, because they are all
      written with a null <span className="wc-id">actor_subject</span>.
    </Alert>
  );
}

function AuditTable({
  entries,
  total,
}: {
  entries: AuditRowView[];
  total: number;
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
            {plural(entries.length, "event", "events")}
            {entries.length < total ? ` of ${String(total)} in the log` : ""}, newest first.
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
