/**
 * One account: what it can reach, what sessions it holds, and its state.
 *
 * This is the screen the console exists for. Four concerns, one panel each, and
 * each panel says what its buttons will actually do:
 *
 *  - **Access.** Grants grouped by app, roles as a set. Adding a role and
 *    removing one are a single click each, which the brief asks for by name.
 *  - **Sessions.** One row per live device, each with its own revoke, plus a
 *    single call that ends every one of them at once. Ward still records no
 *    device name and no address for a family — see the panel's own note.
 *  - **Password.** The only recovery channel an owner-issued account has.
 *  - **State.** Disable and re-enable, with what each one does and does not
 *    bring back written next to the button.
 *
 * ## Where a confirmation is required and where it is in the way
 *
 * Removing one role is one click with no dialog. It is the brief's explicit
 * requirement, it is reversible by the click next to it, and the outcome line
 * names the role that went so it can be put back verbatim. Everything wider
 * than that — revoking an app entirely, ending sessions, rotating a password,
 * disabling an account — is behind a confirmation that names the consequence,
 * because none of those are undone by clicking again.
 */

import { useState } from "react";
import { Link } from "react-router-dom";

import {
  consoleApi,
  type AccountDetailResult,
  type AppView,
  type GrantView,
} from "../../console-api.js";
import { consoleHref } from "./nav.js";
import { formatWhen, plural } from "./format.js";
import { describeGrantRevoke, describeGrantWrite, groupGrantsByApp } from "./grant-set.js";
import { useConsole, useConsoleLoad, useWriter } from "./session.js";
import { Alert, Confirm, Empty, Panel, TextField } from "./ui.js";

export function AccountDetailScreen({ subject }: { subject: string }): React.JSX.Element {
  const { basePath } = useConsole();
  const account = useConsoleLoad(`account:${subject}`, () => consoleApi.getAccount(subject));
  const apps = useConsoleLoad("apps", () => consoleApi.listApps());

  return (
    <>
      <Link className="wc-back" to={consoleHref(basePath, { kind: "accounts" })}>
        Back to accounts
      </Link>

      {account.result.state === "loading" ? <p className="wc-lede">Loading the account…</p> : null}

      {account.result.state === "failed" ? (
        <Alert tone="error" title="The account did not load" takeFocus>
          {account.result.message}
        </Alert>
      ) : null}

      {account.result.state === "ready" ? (
        <AccountBody
          detail={account.result.data}
          apps={apps.result.state === "ready" ? apps.result.data : []}
          reload={account.reload}
        />
      ) : null}
    </>
  );
}

type Pending =
  | { kind: "none" }
  | { kind: "disable" }
  | { kind: "enable" }
  | { kind: "rotate" }
  | { kind: "revokeApp"; appSlug: string; roles: string[] };

function AccountBody({
  detail,
  apps,
  reload,
}: {
  detail: AccountDetailResult;
  apps: AppView[];
  reload: () => void;
}): React.JSX.Element {
  const { account, grants, liveSessions } = detail;
  const writer = useWriter();
  const [pending, setPending] = useState<Pending>({ kind: "none" });
  const [newPassword, setNewPassword] = useState("");

  const close = (): void => {
    setPending({ kind: "none" });
  };

  async function finish(action: () => Promise<boolean>): Promise<void> {
    const ok = await action();
    close();
    if (ok) reload();
  }

  return (
    <>
      <div className="wc-head">
        <h1>{account.username}</h1>
        <span className="wc-state" data-state={account.disabled ? "disabled" : undefined}>
          {account.disabled
            ? `Disabled${account.disabledAt === null ? "" : ` since ${formatWhen(account.disabledAt)}`}`
            : "Active"}
        </span>
      </div>

      <p className="wc-lede">
        Subject <span className="wc-id">{account.subject}</span> — the value that appears in this
        account&rsquo;s access tokens and in every grant row below. Created{" "}
        {formatWhen(account.createdAt)}.
        {account.email === null
          ? " No email address: this account was created from the console, so it has no reset link."
          : ` Email ${account.email}${account.emailVerified ? " (verified)" : " (unverified)"}.`}
      </p>

      {writer.error === undefined ? null : (
        <Alert tone="error" title="Ward refused the change" takeFocus>
          {writer.error}
        </Alert>
      )}

      <AccessPanel
        subject={account.subject}
        grants={grants}
        apps={apps}
        onRevokeApp={(appSlug, roles) => {
          setPending({ kind: "revokeApp", appSlug, roles });
        }}
        reload={reload}
      />

      <SessionsPanel subject={account.subject} onChanged={reload} />

      <Panel
        title="Password"
        note="The only recovery channel this account has. Set a new one here and tell the person out of band; Ward never shows a password back, and this console never puts one in a URL."
      >
        <form
          className="wc-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (newPassword !== "") setPending({ kind: "rotate" });
          }}
        >
          <TextField
            label="New password"
            name="new-password"
            type="password"
            value={newPassword}
            onChange={setNewPassword}
            autoComplete="new-password"
            required
            disabled={writer.busy}
            hint="At least 8 characters. Every live session for this account ends when it is set."
          />
          <div className="wc-actions">
            <button type="submit" className="wc-btn" disabled={writer.busy || newPassword === ""}>
              Rotate password
            </button>
          </div>
        </form>
      </Panel>

      <Panel
        title="Account state"
        tone={account.disabled ? undefined : "danger"}
        note={
          account.disabled
            ? "Re-enabling restores the grants exactly as they are above — they were never touched. It does not bring the revoked sessions back; the person signs in again."
            : "Disabling locks the account and revokes its live sessions in the same write, so the sessions genuinely end rather than only future sign-ins being blocked. The grants survive, so a later re-enable restores exactly what is above."
        }
      >
        <div className="wc-actions">
          {account.disabled ? (
            <button
              type="button"
              className="wc-btn"
              data-tone="primary"
              disabled={writer.busy}
              onClick={() => {
                setPending({ kind: "enable" });
              }}
            >
              Re-enable account
            </button>
          ) : (
            <button
              type="button"
              className="wc-btn"
              data-tone="danger"
              disabled={writer.busy}
              onClick={() => {
                setPending({ kind: "disable" });
              }}
            >
              Disable account
            </button>
          )}
        </div>
      </Panel>

      <Confirm
        open={pending.kind === "disable"}
        title={`Disable ${account.username}?`}
        confirmLabel="Disable and end sessions"
        busy={writer.busy}
        onCancel={close}
        onConfirm={() => {
          void finish(() =>
            writer.run(
              () => consoleApi.disableAccount(account.subject),
              (result) =>
                result.sessionsRevoked === 0
                  ? `Disabled ${account.username}. It held no live sessions.`
                  : `Disabled ${account.username} and revoked ${plural(result.sessionsRevoked, "session", "sessions")}.`,
            ),
          );
        }}
      >
        <p>
          The account will no longer be able to sign in, and its{" "}
          {plural(liveSessions, "live session", "live sessions")} will be revoked immediately rather
          than left to expire.
        </p>
        <p>
          Its {plural(grants.length, "grant", "grants")} will be left in place, so re-enabling
          restores exactly the access shown above.
        </p>
      </Confirm>

      <Confirm
        open={pending.kind === "enable"}
        title={`Re-enable ${account.username}?`}
        confirmLabel="Re-enable"
        tone="primary"
        busy={writer.busy}
        onCancel={close}
        onConfirm={() => {
          void finish(() =>
            writer.run(
              () => consoleApi.enableAccount(account.subject),
              (result) =>
                result.changed
                  ? `Re-enabled ${account.username}. Its grants came back with it; its old sessions did not.`
                  : `${account.username} was already enabled. Nothing changed and no audit row was written.`,
            ),
          );
        }}
      >
        <p>
          The account will be able to sign in again, with the{" "}
          {plural(grants.length, "grant", "grants")} shown above. The sessions revoked when it was
          disabled stay revoked.
        </p>
      </Confirm>

      <Confirm
        open={pending.kind === "rotate"}
        title={`Rotate the password for ${account.username}?`}
        confirmLabel="Set the new password"
        busy={writer.busy}
        onCancel={close}
        onConfirm={() => {
          void finish(async () => {
            const ok = await writer.run(
              () => consoleApi.setPassword(account.subject, newPassword),
              (result) =>
                `Password rotated. ${
                  result.sessionsRevoked === 0
                    ? "There were no live sessions to end."
                    : `${plural(result.sessionsRevoked, "session", "sessions")} ended with it.`
                }`,
            );
            // Out of state either way: a password must not sit in the form
            // after the request that carried it.
            setNewPassword("");
            return ok;
          });
        }}
      >
        <p>
          The account&rsquo;s password will be replaced and its{" "}
          {plural(liveSessions, "live session", "live sessions")} revoked, because a rotation that
          leaves a thirty-day refresh token alive has not achieved the thing it was performed for.
        </p>
        <p>
          Ward will not show the new password again. Pass it on before you leave this page — there
          is no reset link for an account created in this console.
        </p>
      </Confirm>

      <Confirm
        open={pending.kind === "revokeApp"}
        title={
          pending.kind === "revokeApp"
            ? `Revoke all access to ${pending.appSlug}?`
            : "Revoke app access?"
        }
        confirmLabel="Revoke every role"
        busy={writer.busy}
        onCancel={close}
        onConfirm={() => {
          if (pending.kind !== "revokeApp") return;
          const appSlug = pending.appSlug;
          void finish(() =>
            writer.run(
              () => consoleApi.revokeGrant({ subject: account.subject, appSlug }),
              (result) => describeGrantRevoke(appSlug, result.removed, result.roles),
            ),
          );
        }}
      >
        <p>
          {pending.kind === "revokeApp"
            ? `Every role ${account.username} holds in ${pending.appSlug} will be removed: ${pending.roles.join(", ")}.`
            : ""}
        </p>
        <p>
          The account keeps its access to every other app. Access tokens already minted stay valid
          for up to fifteen minutes, so the app may still admit it until they expire.
        </p>
      </Confirm>
    </>
  );
}

/**
 * The account's live sessions — one row per device, not a count.
 *
 * `GET /console/accounts/:subject/sessions` lists the newest live refresh row
 * per family. `issuedAt` is that row's own issuance — the **last refresh**,
 * not the original sign-in — because the family's first row is deliberately
 * not fetched: it would be one extra query per device to report a timestamp
 * nobody can act on, where a refresh four minutes ago is the fact that says
 * whether a device is in use.
 *
 * Ward records no device name and no address for a family: `refresh_tokens`
 * has no such column. A family id is the only handle a session has here, and
 * this panel says so rather than letting a list of rows imply an operator can
 * tell which device is which.
 */
function SessionsPanel({
  subject,
  onChanged,
}: {
  subject: string;
  onChanged: () => void;
}): React.JSX.Element {
  const sessions = useConsoleLoad(`sessions:${subject}`, () => consoleApi.listSessions(subject));
  const writer = useWriter();
  const [revoking, setRevoking] = useState<string | undefined>();
  const [endingAll, setEndingAll] = useState(false);

  async function revokeOne(familyId: string): Promise<void> {
    const ok = await writer.run(
      () => consoleApi.revokeSession(subject, familyId),
      (result) =>
        result.changed
          ? "That session was ended. The device signs out the next time it tries to refresh."
          : "That session had already ended.",
    );
    setRevoking(undefined);
    if (ok) {
      sessions.reload();
      onChanged();
    }
  }

  async function revokeAll(): Promise<void> {
    const ok = await writer.run(
      () => consoleApi.revokeAllSessions(subject),
      (result) =>
        result.revoked === 0
          ? "No live sessions to end."
          : `Ended ${plural(result.revoked, "session", "sessions")}. The account itself was untouched.`,
    );
    setEndingAll(false);
    if (ok) {
      sessions.reload();
      onChanged();
    }
  }

  return (
    <Panel
      title="Sessions"
      note="Ward keeps no device name and no address for a live session — refresh_tokens has no such column — so a family id below is the only handle it has. What's shown as issued is the last refresh, not the original sign-in."
    >
      {writer.error === undefined ? null : (
        <Alert tone="error" title="The session was not ended" takeFocus>
          {writer.error}
        </Alert>
      )}

      {sessions.result.state === "loading" ? (
        <p className="wc-panel-note">Loading sessions…</p>
      ) : null}

      {sessions.result.state === "failed" ? (
        <Alert tone="error" title="The sessions did not load">
          {sessions.result.message}
        </Alert>
      ) : null}

      {sessions.result.state === "ready" ? (
        sessions.result.data.sessions.length === 0 ? (
          <Empty title="No live sessions">
            <p>Nothing is currently signed in as this account.</p>
          </Empty>
        ) : (
          <>
            <div className="wc-table-scroll">
              <table className="wc-table">
                <caption>
                  {plural(sessions.result.data.sessions.length, "live session", "live sessions")}.
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Device</th>
                    <th scope="col">Last refreshed</th>
                    <th scope="col">Expires</th>
                    <th scope="col">
                      <span className="wc-sr">Revoke</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.result.data.sessions.map((session) => (
                    <tr key={session.familyId}>
                      <td className="wc-id">{session.familyId}</td>
                      <td>{formatWhen(session.issuedAt)}</td>
                      <td>{formatWhen(session.expiresAt)}</td>
                      <td>
                        <button
                          type="button"
                          className="wc-btn-link"
                          disabled={writer.busy}
                          onClick={() => {
                            setRevoking(session.familyId);
                          }}
                        >
                          End this session
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="wc-actions">
              <button
                type="button"
                className="wc-btn"
                data-tone="danger"
                disabled={writer.busy}
                onClick={() => {
                  setEndingAll(true);
                }}
              >
                End all sessions
              </button>
              <span className="wc-field-hint">
                Rotating the password below also ends every session, and is the better move if the
                password itself is what you no longer trust.
              </span>
            </div>
          </>
        )
      ) : null}

      <Confirm
        open={revoking !== undefined}
        title="End this session?"
        confirmLabel="End session"
        busy={writer.busy}
        onCancel={() => {
          setRevoking(undefined);
        }}
        onConfirm={() => {
          if (revoking !== undefined) void revokeOne(revoking);
        }}
      >
        <p>
          The device on this session is signed out the next time it tries to refresh its access
          token — within about fifteen minutes if it is in active use.
        </p>
      </Confirm>

      <Confirm
        open={endingAll}
        title="End every session for this account?"
        confirmLabel="End all sessions"
        busy={writer.busy}
        onCancel={() => {
          setEndingAll(false);
        }}
        onConfirm={() => {
          void revokeAll();
        }}
      >
        <p>
          Every live session ends in one call. The account&rsquo;s grants, password and email are
          untouched, and it can sign in again immediately — this is the whole difference from
          disabling it.
        </p>
      </Confirm>
    </Panel>
  );
}

/** The oldest grant in a set — who opened this app to this account, and when. */
function earliest(grants: GrantView[]): GrantView {
  return grants.reduce((oldest, grant) => (grant.grantedAt < oldest.grantedAt ? grant : oldest));
}

/**
 * Grants, grouped by app, roles as a set.
 *
 * ## No dropdown of known roles, ever
 *
 * Ward stores a role string opaquely and never interprets it, and a picker
 * listing "the roles" would quietly become the schema Ward deliberately does
 * not have — an app growing a capability would then need this console
 * redeployed. So the role field is free text, and the roles already in use in
 * the selected app are offered as `<datalist>` suggestions: helpful, and not a
 * constraint.
 */
function AccessPanel({
  subject,
  grants,
  apps,
  onRevokeApp,
  reload,
}: {
  subject: string;
  grants: GrantView[];
  apps: AppView[];
  onRevokeApp: (appSlug: string, roles: string[]) => void;
  reload: () => void;
}): React.JSX.Element {
  const grouped = groupGrantsByApp(grants);
  const writer = useWriter();
  const [appSlug, setAppSlug] = useState("");
  const [role, setRole] = useState("");

  // Roles already in use in the selected app, for the suggestion list. Loaded
  // per app rather than estate-wide because there is no endpoint that lists
  // every grant — deliberately, since that is not a question anyone asks.
  const suggestions = useConsoleLoad(`app-grants:${appSlug}`, () =>
    appSlug === "" ? Promise.resolve([]) : consoleApi.grantsForApp(appSlug),
  );
  const suggested =
    suggestions.result.state === "ready"
      ? [...new Set(suggestions.result.data.map((grant) => grant.role))].sort()
      : [];

  async function add(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    if (appSlug === "" || role === "") return;
    const ok = await writer.run(
      () => consoleApi.addGrant({ subject, appSlug, role }),
      (result) => describeGrantWrite(result.grant.role, result.grant.appSlug, result.created),
    );
    if (ok) {
      setRole("");
      reload();
    }
  }

  async function drop(targetApp: string, targetRole: string): Promise<void> {
    const ok = await writer.run(
      () => consoleApi.revokeGrant({ subject, appSlug: targetApp, role: targetRole }),
      (result) => describeGrantRevoke(targetApp, result.removed, result.roles),
    );
    if (ok) reload();
  }

  return (
    <Panel
      title="Access"
      note="A grant is the estate's actual security boundary: this account can use exactly the apps listed here, as exactly these roles, and nothing else. There is no wildcard — even the owner account holds one explicit row per app."
    >
      {writer.error === undefined ? null : (
        <Alert tone="error" title="The grant was not written" takeFocus>
          {writer.error}
        </Alert>
      )}

      {grouped.length === 0 ? (
        <Empty title="No grants">
          <p>
            This account holds no grants, so it can sign in to Ward and reach <strong>none</strong>{" "}
            of the estate&rsquo;s apps. <em>This is the default for every new account</em> — it is
            not a page that failed to load.
          </p>
          <p>Issue one below. Access begins the moment the row exists; nothing needs a deploy.</p>
        </Empty>
      ) : (
        <div>
          {grouped.map((entry) => (
            <div className="wc-app-grant" key={entry.appSlug}>
              <h3>{entry.appSlug}</h3>
              <p className="wc-app-grant-meta">
                {plural(entry.roles.length, "role", "roles")}, first granted{" "}
                {formatWhen(earliest(entry.grants).grantedAt)} by{" "}
                {/* `grantedBy` is a subject, or the literal `superuser` /
                    `self-registration`. It is not a foreign key and must never
                    be rendered as a link to an account. */}
                <span className="wc-id">{earliest(entry.grants).grantedBy}</span>
              </p>
              <ul className="wc-roles">
                {entry.grants.map((grant) => (
                  <li className="wc-role" key={grant.role}>
                    <span>{grant.role}</span>
                    <button
                      type="button"
                      className="wc-role-drop"
                      disabled={writer.busy}
                      title={`Remove ${grant.role} in ${entry.appSlug}`}
                      onClick={() => {
                        void drop(entry.appSlug, grant.role);
                      }}
                    >
                      <span aria-hidden="true">×</span>
                      <span className="wc-sr">{`Remove the role ${grant.role} in ${entry.appSlug}`}</span>
                    </button>
                  </li>
                ))}
                <li>
                  <button
                    type="button"
                    className="wc-btn-link"
                    disabled={writer.busy}
                    onClick={() => {
                      onRevokeApp(entry.appSlug, entry.roles);
                    }}
                  >
                    Revoke all access to {entry.appSlug}
                  </button>
                </li>
              </ul>
            </div>
          ))}
        </div>
      )}

      <form
        className="wc-form wc-form-row wc-grant-add"
        onSubmit={(event) => {
          void add(event);
        }}
      >
        <p className="wc-field">
          <label htmlFor="wc-grant-app">App</label>
          <select
            id="wc-grant-app"
            value={appSlug}
            disabled={writer.busy}
            onChange={(event) => {
              setAppSlug(event.target.value);
            }}
          >
            <option value="">Choose an app…</option>
            {apps.map((app) => (
              <option key={app.slug} value={app.slug}>
                {app.slug} — {app.name}
              </option>
            ))}
          </select>
        </p>
        <TextField
          label="Role"
          name="role"
          value={role}
          onChange={setRole}
          autoComplete="off"
          spellCheck={false}
          opaque
          disabled={writer.busy}
          list="wc-role-suggestions"
          placeholder="admin"
        />
        <datalist id="wc-role-suggestions">
          {suggested.map((value) => (
            <option key={value} value={value} />
          ))}
        </datalist>
        <p className="wc-row-actions">
          <button
            type="submit"
            className="wc-btn"
            data-tone="primary"
            disabled={writer.busy || appSlug === "" || role === ""}
          >
            Add role
          </button>
        </p>
      </form>

      <p className="wc-panel-note">
        The role is free text and the suggestions are only the roles already in use in the app you
        pick. Ward never interprets a role, so there is no list of known ones to choose from — a
        picker here would quietly become a schema Ward deliberately does not have.
      </p>
    </Panel>
  );
}
