/**
 * One app: its name, its registration flag, who can reach it, and removing it.
 *
 * ## The registration flag is the only anonymous write surface in Ward
 *
 * Everything else on this console needs an invitation somewhere in its history.
 * Turning this flag on means a stranger on the public internet can create an
 * account and be granted a role by doing so, which is why it is behind a
 * confirmation that names the app and the role rather than a switch that
 * toggles under the cursor.
 *
 * Opening also requires naming the baseline role in the same request, and
 * closing clears it, so a later reopen cannot silently inherit an answer nobody
 * re-checked. The form here mirrors that: one control, one confirmation, one
 * `PATCH`.
 *
 * ## Renaming and opening are different questions
 *
 * A rename writes `app.update`; a change to the flag writes `app.registration`.
 * The audit log asks "who renamed this" and "who opened this to the public"
 * separately, so they are separate forms here — submitting one never quietly
 * carries the other.
 */

import { useState } from "react";
import { Link } from "react-router-dom";

import { consoleApi, type AppView, type GrantView } from "../../console-api.js";
import { consoleHref } from "./nav.js";
import { formatWhen, plural } from "./format.js";
import { useConsole, useConsoleLoad, useWriter } from "./session.js";
import { AppKeysPanel } from "./AppKeys.js";
import { Alert, Confirm, Empty, Panel, TextField } from "./ui.js";

export function AppDetailScreen({ slug }: { slug: string }): React.JSX.Element {
  const { basePath } = useConsole();
  const app = useConsoleLoad(`app:${slug}`, () => consoleApi.getApp(slug));
  const grants = useConsoleLoad(`app-grants:${slug}`, () => consoleApi.grantsForApp(slug));

  return (
    <>
      <Link className="wc-back" to={consoleHref(basePath, { kind: "apps" })}>
        Back to apps
      </Link>

      {app.result.state === "loading" ? <p className="wc-lede">Loading the app…</p> : null}

      {app.result.state === "failed" ? (
        <Alert tone="error" title="The app did not load" takeFocus>
          {app.result.message}
        </Alert>
      ) : null}

      {app.result.state === "ready" ? (
        <AppBody
          app={app.result.data.app}
          grantCount={app.result.data.grantCount}
          grants={grants.result.state === "ready" ? grants.result.data : []}
          basePath={basePath}
          reload={() => {
            app.reload();
            grants.reload();
          }}
        />
      ) : null}
    </>
  );
}

type Pending = { kind: "none" } | { kind: "open" } | { kind: "close" } | { kind: "delete" };

function AppBody({
  app,
  grantCount,
  grants,
  basePath,
  reload,
}: {
  app: AppView;
  grantCount: number;
  grants: GrantView[];
  basePath: string;
  reload: () => void;
}): React.JSX.Element {
  const writer = useWriter();
  const [name, setName] = useState(app.name);
  const [baselineRole, setBaselineRole] = useState(app.baselineRole ?? "");
  const [pending, setPending] = useState<Pending>({ kind: "none" });
  const [deleted, setDeleted] = useState(false);

  const close = (): void => {
    setPending({ kind: "none" });
  };

  if (deleted) {
    return (
      <Alert tone="done" title={`${app.slug} was removed`} takeFocus>
        The app and every grant for it are gone.{" "}
        <Link to={consoleHref(basePath, { kind: "apps" })}>Back to the registry</Link>.
      </Alert>
    );
  }

  return (
    <>
      <div className="wc-head">
        <h1>{app.name}</h1>
        <span className="wc-id">{app.slug}</span>
        {app.publicRegistration ? (
          <span className="wc-state" data-state="open">
            Open to public registration
          </span>
        ) : (
          <span className="wc-state">Closed to strangers</span>
        )}
      </div>

      <p className="wc-lede">
        Registered {formatWhen(app.createdAt)}, last changed {formatWhen(app.updatedAt)}.{" "}
        {plural(grantCount, "grant", "grants")} {grantCount === 1 ? "names" : "name"} this app.
      </p>

      {writer.error === undefined ? null : (
        <Alert tone="error" title="Ward refused the change" takeFocus>
          {writer.error}
        </Alert>
      )}

      <Panel
        title="Name"
        note="The display name only. The slug is permanent: it is what grants, access tokens and every audit row for this app are keyed on."
      >
        <form
          className="wc-form"
          onSubmit={(event) => {
            event.preventDefault();
            void writer
              .run(
                () => consoleApi.patchApp(app.slug, { name }),
                (updated) =>
                  updated.name === app.name
                    ? `The name was already ${updated.name}. Nothing changed and no audit row was written.`
                    : `Renamed ${app.slug} to ${updated.name}.`,
              )
              .then((ok) => {
                if (ok) reload();
              });
          }}
        >
          <TextField
            label="Display name"
            name="name"
            value={name}
            onChange={setName}
            autoComplete="off"
            required
            disabled={writer.busy}
          />
          <div className="wc-actions">
            <button
              type="submit"
              className="wc-btn"
              disabled={writer.busy || name === "" || name === app.name}
            >
              Save the name
            </button>
          </div>
        </form>
      </Panel>

      <Panel
        title="Public registration"
        tone={app.publicRegistration ? "notice" : undefined}
        note={
          app.publicRegistration ? (
            <>
              This app is <strong>open</strong>. Anyone who can reach Ward may create an account
              without an invitation, and each one is granted{" "}
              <span className="wc-id">{app.baselineRole ?? "nothing"}</span> in this app on sign-up.
            </>
          ) : (
            <>
              This app is <strong>closed</strong>. Accounts for it exist only because the operator
              created them and issued a grant. This is the default, and it is the reason a newly
              registered app is reachable by nobody.
            </>
          )
        }
      >
        {app.publicRegistration ? (
          <div className="wc-actions">
            <button
              type="button"
              className="wc-btn"
              data-tone="primary"
              disabled={writer.busy}
              onClick={() => {
                setPending({ kind: "close" });
              }}
            >
              Close registration
            </button>
            <span className="wc-field-hint">
              Closing clears the baseline role, so reopening later has to name one again.
            </span>
          </div>
        ) : (
          <form
            className="wc-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (baselineRole !== "") setPending({ kind: "open" });
            }}
          >
            <TextField
              label="Baseline role a stranger would get"
              name="baseline-role"
              value={baselineRole}
              onChange={setBaselineRole}
              autoComplete="off"
              spellCheck={false}
              opaque
              required
              disabled={writer.busy}
              placeholder="reader"
              hint="Ward will not open an app without one, in the same request. Free text — Ward never interprets a role."
            />
            <div className="wc-actions">
              <button
                type="submit"
                className="wc-btn"
                data-tone="danger"
                disabled={writer.busy || baselineRole === ""}
              >
                Open registration…
              </button>
            </div>
          </form>
        )}
      </Panel>

      <Panel
        title="Who can reach this app"
        note="Every grant naming this app. Closing registration does not evict anyone already here; removing a grant does."
      >
        {grants.length === 0 ? (
          <Empty title="Nobody">
            <p>
              No account holds a grant in <span className="wc-id">{app.slug}</span>, so nobody can
              use it — not even the owner account. For a newly registered app that is the expected
              state, not a fault.
            </p>
            <p>Issue grants from each account&rsquo;s page.</p>
          </Empty>
        ) : (
          <div className="wc-table-scroll">
            <table className="wc-table">
              <caption>{plural(grants.length, "grant", "grants")}.</caption>
              <thead>
                <tr>
                  <th scope="col">Subject</th>
                  <th scope="col">Role</th>
                  <th scope="col">Granted</th>
                  <th scope="col">By</th>
                </tr>
              </thead>
              <tbody>
                {grants.map((grant) => (
                  <tr key={`${grant.subject}:${grant.role}`}>
                    <th scope="row">
                      <Link
                        to={consoleHref(basePath, { kind: "account", subject: grant.subject })}
                        className="wc-id"
                      >
                        {grant.subject}
                      </Link>
                    </th>
                    <td>
                      <span className="wc-id">{grant.role}</span>
                    </td>
                    <td className="wc-when">
                      <time dateTime={grant.grantedAt} title={grant.grantedAt}>
                        {formatWhen(grant.grantedAt)}
                      </time>
                    </td>
                    {/* Not a link. `grantedBy` is a subject or the literal
                        `superuser` / `self-registration`; it is not a foreign
                        key and there may be no account behind it at all. */}
                    <td>
                      <span className="wc-id">{grant.grantedBy}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/*
        Above "Remove this app", below the grants: an app's keys are ordinary
        operational state, not a hazard, and burying them under the delete
        panel would put the routine action after the irreversible one.
      */}
      <AppKeysPanel slug={app.slug} />

      <Panel
        title="Remove this app"
        tone="danger"
        note="Deleting an app removes every grant for it — and every service key — in the same write. It is the one action on this console that silently removes rows you did not name — the audit row records how many went, and that count is the only trace they existed."
      >
        <div className="wc-actions">
          <button
            type="button"
            className="wc-btn"
            data-tone="danger"
            disabled={writer.busy}
            onClick={() => {
              setPending({ kind: "delete" });
            }}
          >
            Remove {app.slug}
          </button>
        </div>
      </Panel>

      <Confirm
        open={pending.kind === "open"}
        title={`Open ${app.slug} to the public internet?`}
        confirmLabel="Open registration"
        busy={writer.busy}
        onCancel={close}
        onConfirm={() => {
          void writer
            .run(
              () => consoleApi.patchApp(app.slug, { publicRegistration: true, baselineRole }),
              (updated) =>
                `Registration opened for ${updated.slug}. Strangers who sign up get ${String(updated.baselineRole)}.`,
            )
            .then((ok) => {
              close();
              if (ok) reload();
            });
        }}
      >
        <p>
          Anyone who can reach Ward will be able to create an account for{" "}
          <span className="wc-id">{app.slug}</span> without an invitation, and each will be granted{" "}
          <span className="wc-id">{baselineRole}</span> in it automatically.
        </p>
        <p>
          This is the only setting in Ward that exposes an anonymous write surface on the public
          internet. It writes an <span className="wc-id">app.registration</span> audit row, which is
          the row to look for when asking who opened an app.
        </p>
      </Confirm>

      <Confirm
        open={pending.kind === "close"}
        title={`Close registration for ${app.slug}?`}
        confirmLabel="Close registration"
        tone="primary"
        busy={writer.busy}
        onCancel={close}
        onConfirm={() => {
          void writer
            .run(
              () =>
                consoleApi.patchApp(app.slug, { publicRegistration: false, baselineRole: null }),
              (updated) =>
                `Registration closed for ${updated.slug}. The baseline role was cleared with it.`,
            )
            .then((ok) => {
              close();
              if (ok) {
                setBaselineRole("");
                reload();
              }
            });
        }}
      >
        <p>
          No new accounts can be self-created for this app. The baseline role{" "}
          <span className="wc-id">{app.baselineRole ?? "none"}</span> is cleared, so reopening later
          has to name one again — a reopen must not inherit an answer nobody re-checked.
        </p>
        <p>
          The {plural(grants.length, "person", "people")} already holding a grant here keep it.
          Closing registration stops new strangers; it does not evict anyone.
        </p>
      </Confirm>

      <Confirm
        open={pending.kind === "delete"}
        title={`Remove ${app.slug} from the registry?`}
        confirmLabel={`Remove ${app.slug} and ${plural(grantCount, "grant", "grants")}`}
        busy={writer.busy}
        onCancel={close}
        onConfirm={() => {
          void writer
            .run(
              () => consoleApi.deleteApp(app.slug),
              (result) =>
                `Removed ${result.slug} and ${plural(result.grantsRevoked, "grant", "grants")} with it.`,
            )
            .then((ok) => {
              close();
              if (ok) setDeleted(true);
            });
        }}
      >
        <p>
          {plural(grantCount, "grant", "grants")} will be deleted along with the app, and everyone
          holding one loses access to it. Ward keeps no copy of which roles they were.
        </p>
        <p>
          Re-registering the same slug afterwards creates an app that nobody can reach: the grants
          do not come back.
        </p>
      </Confirm>
    </>
  );
}
