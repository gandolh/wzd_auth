/**
 * One app's service keys — issuing, seeing, and turning off.
 *
 * ## The key is shown once, and this component is the only place it exists
 *
 * Ward stores `sha256(key)` and has no route that reads a key back, so the
 * plaintext lives in this component's state and nowhere else — not in
 * `localStorage`, not in a `Loadable`, not in the list this panel renders
 * afterwards. Reloading the page loses it, which is correct and is said out
 * loud rather than being discovered.
 *
 * The revealed key is deliberately **not** auto-dismissed on a timer. An
 * operator pasting a value into a `.env` on another machine must not have it
 * vanish mid-typing, and a timer would trade a real workflow for the appearance
 * of security on a value that is already in their clipboard.
 *
 * ## Revoking is an outage, and the confirmation says which one
 *
 * There is no cache in front of the key check, so a revoked key stops working
 * on the app's very next request — not within the 30 seconds a session
 * revocation takes. If it is the app's only live key, every one of that app's
 * users is refused seconds later. The confirmation names the app rather than
 * the key id, because "atrium" is what an operator recognises and
 * `3f2a…` is not.
 *
 * ## Rotation is why more than one key may be live
 *
 * The safe order is: issue the new one, deploy it, watch `lastUsedAt` on the
 * old one stop moving, then revoke the old one. The panel is laid out to make
 * that legible — the "last used" column is the one that tells an operator
 * whether revoking is safe yet, and it is coarse (Ward stamps it at most
 * hourly), so it is rendered as a date and never as a precise time.
 */

import { useState } from "react";

import { consoleApi, type AppKeyView } from "../../console-api.js";
import { formatWhen, plural } from "./format.js";
import { useConsoleLoad, useWriter } from "./session.js";
import { Alert, Confirm, Empty, Id, Panel, TextField } from "./ui.js";

export function AppKeysPanel({ slug }: { slug: string }): React.JSX.Element {
  const keys = useConsoleLoad(`app-keys:${slug}`, () => consoleApi.keysForApp(slug));
  const writer = useWriter();

  const [label, setLabel] = useState("");
  /**
   * The plaintext of the key just issued. Cleared when another is issued, and
   * never written anywhere else. `undefined` is "nothing to show", which is
   * every state but the one immediately after a successful issue.
   */
  const [revealed, setRevealed] = useState<string | undefined>(undefined);
  const [pendingRevoke, setPendingRevoke] = useState<AppKeyView | undefined>(undefined);

  const rows = keys.result.state === "ready" ? keys.result.data : [];
  const live = rows.filter((row) => !row.revoked);

  async function issue(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    const trimmed = label.trim();
    if (trimmed === "") return;

    setRevealed(undefined);

    // The plaintext is stashed inside the action, because it exists only in
    // this one response — `writer.run` reports whether the write succeeded, not
    // what it returned, and refetching the list afterwards would come back with
    // the digest-backed row and no key on it.
    const ok = await writer.run(
      async () => {
        const created = await consoleApi.createAppKey(slug, trimmed);
        setRevealed(created.key);
        return created;
      },
      (result) => `Issued the key "${result.appKey.label}" for ${slug}. It is shown once.`,
    );

    if (ok) {
      setLabel("");
      keys.reload();
    }
  }

  return (
    <Panel
      title="Service keys"
      note={
        <>
          The credential this app presents on every <Id>POST /ward-api/introspect</Id> call. Without
          a live key the app can authenticate nobody. Ward stores only a digest, so a key is shown
          once and cannot be recovered — replace a lost one rather than looking for it.
        </>
      }
    >
      {keys.result.state === "loading" ? <p className="wc-lede">Loading the keys…</p> : null}

      {keys.result.state === "failed" ? (
        <Alert tone="error" title="The keys did not load">
          {keys.result.message}
        </Alert>
      ) : null}

      {writer.error === undefined ? null : (
        <Alert tone="error" title="That did not work" takeFocus>
          {writer.error}
        </Alert>
      )}

      {revealed === undefined ? null : (
        <Alert tone="notice" title="Copy this key now — it is not shown again" takeFocus>
          <p>
            Put it in the app&rsquo;s server-side environment as <Id>WARD_APP_KEY</Id>. It is a
            secret: it must never reach a browser bundle or a client-side config.
          </p>
          <pre className="wc-key-reveal">{revealed}</pre>
          <p>
            <button type="button" className="wc-btn" onClick={() => setRevealed(undefined)}>
              I have copied it
            </button>
          </p>
        </Alert>
      )}

      <form className="wc-form" onSubmit={(event) => void issue(event)}>
        <TextField
          label="Label"
          name="app-key-label"
          value={label}
          onChange={setLabel}
          hint="What tells this key apart from the app's other keys — “production”, “laptop”."
        />
        <button type="submit" className="wc-btn" data-tone="primary" disabled={writer.busy}>
          {writer.busy ? "Issuing…" : "Issue a key"}
        </button>
      </form>

      {keys.result.state === "ready" && rows.length === 0 ? (
        <Empty title="No keys">
          <p>
            This app holds no service key, so it cannot call <Id>/introspect</Id> and every request
            it serves will be refused. Issue one above and put it in the app&rsquo;s environment.
          </p>
        </Empty>
      ) : null}

      {rows.length === 0 ? null : (
        <>
          <p className="wc-panel-note">
            {plural(live.length, "live key", "live keys")}
            {live.length > 1
              ? " — more than one is normal during a rotation, and is how a rotation avoids an outage."
              : null}
          </p>
          <table className="wc-table">
            <thead>
              <tr>
                <th scope="col">Label</th>
                <th scope="col">Id</th>
                <th scope="col">Issued</th>
                <th scope="col">Last used</th>
                <th scope="col">
                  <span className="wc-sr">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} data-revoked={row.revoked ? "true" : undefined}>
                  <td>
                    {row.label}
                    {row.revoked ? (
                      <>
                        {" "}
                        <span className="wc-state" data-state="disabled">
                          revoked
                        </span>
                      </>
                    ) : null}
                  </td>
                  <td>
                    <Id>{row.id}</Id>
                  </td>
                  <td>
                    <time dateTime={row.createdAt} title={row.createdAt}>
                      {formatWhen(row.createdAt)}
                    </time>
                  </td>
                  <td>
                    {row.lastUsedAt === null ? (
                      // Never used at all — which for a key that has been
                      // deployed a while usually means it is not the one the
                      // app is actually presenting.
                      <span className="wc-state" data-state="none">
                        never
                      </span>
                    ) : (
                      <time dateTime={row.lastUsedAt} title={`${row.lastUsedAt} (recorded hourly)`}>
                        {formatWhen(row.lastUsedAt)}
                      </time>
                    )}
                  </td>
                  <td>
                    {row.revoked ? (
                      <span className="wc-state" data-state="none">
                        {row.revokedAt === null ? "revoked" : formatWhen(row.revokedAt)}
                      </span>
                    ) : (
                      <button
                        type="button"
                        className="wc-btn"
                        data-tone="danger"
                        onClick={() => setPendingRevoke(row)}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <Confirm
        open={pendingRevoke !== undefined}
        title={`Revoke "${pendingRevoke?.label ?? ""}"?`}
        confirmLabel="Revoke the key"
        busy={writer.busy}
        onCancel={() => setPendingRevoke(undefined)}
        onConfirm={() => {
          const target = pendingRevoke;
          if (target === undefined) return;
          void writer
            .run(
              () => consoleApi.revokeAppKey(target.id),
              (result) => `Revoked "${result.label}". ${slug} can no longer use it.`,
            )
            .then((ok) => {
              setPendingRevoke(undefined);
              if (ok) keys.reload();
            });
        }}
      >
        <p>
          <strong>{slug}</strong> stops being able to use this key immediately — on its very next
          request, not after a cache window.
        </p>
        {live.length <= 1 ? (
          <p>
            This is <strong>the only live key for {slug}</strong>. Revoking it means every one of
            that app&rsquo;s users is refused within seconds, until a new key is issued and
            deployed.
          </p>
        ) : (
          <p>
            {slug} holds {plural(live.length - 1, "other live key", "other live keys")}, so it keeps
            working if one of those is the key it actually presents. Check the “last used” column
            before confirming.
          </p>
        )}
        <p>There is no un-revoke. Issuing a replacement is one step above.</p>
      </Confirm>
    </Panel>
  );
}
