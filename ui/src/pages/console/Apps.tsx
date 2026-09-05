/**
 * The apps registry: the list, and the form that registers a new one.
 *
 * ## Registration is one decision, not two errors
 *
 * Ward refuses to open an app to public self-registration without being told,
 * in the same request, what role a stranger gets — `baseline_role_required` —
 * and it equally refuses a baseline role on a closed app,
 * `baseline_role_requires_open`. Those are two ways of saying that "open" and
 * "confers what?" are halves of one decision.
 *
 * So the form joins them: ticking the box reveals a required role field, and
 * neither can be submitted without the other. An operator should never meet
 * either error, and the API's refusal is the backstop rather than the interface.
 *
 * ## Opening registration is confirmed
 *
 * Turning the flag on opens an anonymous write surface on the public internet.
 * That must not be a stray click, so it is behind a confirmation that names the
 * app, the role, and what a stranger will be able to do — here on creation, and
 * on the app's own page for a later flip.
 */

import { useState } from "react";
import { Link } from "react-router-dom";

import { consoleApi, type AppView } from "../../console-api.js";
import { consoleHref } from "./nav.js";
import { formatWhen, plural } from "./format.js";
import { useConsole, useConsoleLoad, useWriter } from "./session.js";
import { Alert, Confirm, Empty, TextField } from "./ui.js";

export function AppsScreen(): React.JSX.Element {
  const { basePath } = useConsole();
  const { result, reload } = useConsoleLoad("apps-list", () => consoleApi.listApps());
  const [creating, setCreating] = useState(false);

  return (
    <>
      <div className="wc-head">
        <h1>Apps</h1>
        <div className="wc-head-actions">
          <button
            type="button"
            className="wc-btn"
            data-tone="primary"
            aria-expanded={creating}
            onClick={() => {
              setCreating((open) => !open);
            }}
          >
            {creating ? "Close the new-app form" : "Register an app"}
          </button>
        </div>
      </div>

      <p className="wc-lede">
        An app has to be registered here before a grant can name it. Registering one takes no
        deploy, and a new app arrives closed to strangers and reachable by nobody — including the
        owner account — until grants are issued for it.
      </p>

      {creating ? (
        <NewAppForm
          onCreated={() => {
            setCreating(false);
            reload();
          }}
        />
      ) : null}

      {result.state === "loading" ? <p className="wc-lede">Loading the registry…</p> : null}

      {result.state === "failed" ? (
        <Alert tone="error" title="The registry did not load" takeFocus>
          {result.message}
        </Alert>
      ) : null}

      {result.state === "ready" ? (
        result.data.length === 0 ? (
          <Empty title="No apps registered">
            <p>
              Ward knows of no apps, so no grant can be issued for anything and the estate has no
              security boundary to configure yet.
            </p>
            <p>Register the estate&rsquo;s apps here — one row each, slug and name.</p>
          </Empty>
        ) : (
          <AppTable apps={result.data} basePath={basePath} />
        )
      ) : null}
    </>
  );
}

function AppTable({ apps, basePath }: { apps: AppView[]; basePath: string }): React.JSX.Element {
  const open = apps.filter((app) => app.publicRegistration).length;
  return (
    <div className="wc-table-scroll">
      <table className="wc-table">
        <caption>
          {plural(apps.length, "app", "apps")} registered,{" "}
          {open === 0 ? "none open to public registration" : `${String(open)} open to strangers`}.
        </caption>
        <thead>
          <tr>
            <th scope="col">Slug</th>
            <th scope="col">Name</th>
            <th scope="col">Public registration</th>
            <th scope="col">Baseline role</th>
            <th scope="col">Updated</th>
          </tr>
        </thead>
        <tbody>
          {apps.map((app) => (
            <tr key={app.slug}>
              <th scope="row">
                <Link to={consoleHref(basePath, { kind: "app", slug: app.slug })}>
                  <span className="wc-id">{app.slug}</span>
                </Link>
              </th>
              <td>{app.name}</td>
              <td>
                {app.publicRegistration ? (
                  <span className="wc-state" data-state="open">
                    Open to strangers
                  </span>
                ) : (
                  <span className="wc-state">Closed</span>
                )}
              </td>
              <td>
                {app.baselineRole === null ? (
                  <span className="wc-state" data-state="none">
                    none
                  </span>
                ) : (
                  <span className="wc-id">{app.baselineRole}</span>
                )}
              </td>
              <td className="wc-when">
                <time dateTime={app.updatedAt} title={app.updatedAt}>
                  {formatWhen(app.updatedAt)}
                </time>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function NewAppForm({ onCreated }: { onCreated: () => void }): React.JSX.Element {
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [open, setOpen] = useState(false);
  const [baselineRole, setBaselineRole] = useState("");
  const [confirming, setConfirming] = useState(false);
  const writer = useWriter();

  async function create(): Promise<void> {
    const ok = await writer.run(
      () =>
        consoleApi.createApp({
          slug,
          name,
          // Both fields, or neither. The API refuses the halves separately and
          // the form never assembles a half.
          ...(open ? { publicRegistration: true, baselineRole } : {}),
        }),
      (app) =>
        app.publicRegistration
          ? `Registered ${app.slug}, open to public registration. A stranger who signs up gets ${String(app.baselineRole)}.`
          : `Registered ${app.slug}, closed to strangers and reachable by nobody until a grant names it.`,
    );
    setConfirming(false);
    if (ok) {
      setSlug("");
      setName("");
      setOpen(false);
      setBaselineRole("");
      onCreated();
    }
  }

  function submit(event: React.FormEvent): void {
    event.preventDefault();
    if (slug === "" || name === "") return;
    if (open) {
      // The one path through this form that needs a deliberate second step.
      setConfirming(true);
      return;
    }
    void create();
  }

  return (
    <section className="wc-panel">
      <h2>Register an app</h2>
      <p className="wc-panel-note">
        The slug is what grants, tokens and the audit log name this app by, and it is permanent —
        renaming later changes the display name only. Keep it to lower-case letters, digits and
        single hyphens.
      </p>

      {writer.error === undefined ? null : (
        <Alert tone="error" title="Ward refused the app" takeFocus>
          {writer.error}
        </Alert>
      )}

      <form className="wc-form" onSubmit={submit}>
        <TextField
          label="Slug"
          name="slug"
          value={slug}
          onChange={setSlug}
          autoComplete="off"
          spellCheck={false}
          opaque
          required
          disabled={writer.busy}
          placeholder="public-resource-map"
          hint="Permanent. It appears in six apps' configuration and in every audit row for this app."
        />
        <TextField
          label="Display name"
          name="name"
          value={name}
          onChange={setName}
          autoComplete="off"
          required
          disabled={writer.busy}
          placeholder="Public Resource Map"
          hint="Shown to people. Change it later as often as you like."
        />

        <p className="wc-check">
          <input
            id="wc-new-app-open"
            type="checkbox"
            checked={open}
            disabled={writer.busy}
            onChange={(event) => {
              setOpen(event.target.checked);
              if (!event.target.checked) setBaselineRole("");
            }}
          />
          <label htmlFor="wc-new-app-open">
            Open this app to public registration — anyone on the internet may create an account for
            it without an invitation.
          </label>
        </p>

        {open ? (
          <TextField
            label="Baseline role a stranger gets"
            name="baseline-role"
            value={baselineRole}
            onChange={setBaselineRole}
            autoComplete="off"
            spellCheck={false}
            opaque
            required
            disabled={writer.busy}
            placeholder="reader"
            hint="Required: Ward will not open an app without being told what signing up confers. Free text — Ward never interprets a role."
          />
        ) : null}

        <div className="wc-actions">
          <button
            type="submit"
            className="wc-btn"
            data-tone="primary"
            disabled={writer.busy || slug === "" || name === "" || (open && baselineRole === "")}
          >
            {open ? "Register and review" : "Register app"}
          </button>
        </div>
      </form>

      <Confirm
        open={confirming}
        title={`Open ${slug === "" ? "this app" : slug} to the public internet?`}
        confirmLabel="Register it open"
        busy={writer.busy}
        onCancel={() => {
          setConfirming(false);
        }}
        onConfirm={() => {
          void create();
        }}
      >
        <p>
          Anyone who can reach Ward will be able to create an account for{" "}
          <span className="wc-id">{slug}</span> without an invitation, and each one will be granted{" "}
          <span className="wc-id">{baselineRole}</span> in it automatically.
        </p>
        <p>
          This is the only setting in Ward that exposes an anonymous write surface. It can be closed
          again from the app&rsquo;s page, which also clears the baseline role — closing it stops
          new strangers arriving and does not evict the ones already inside.
        </p>
      </Confirm>
    </section>
  );
}
