/**
 * The accounts list, and the form that creates one.
 *
 * **This screen is on the critical path of the estate's cutover.** The owner
 * account — the ordinary Ward account that actually runs the six apps, as
 * against the break-glass credential that reaches only this console — comes into
 * existence here and nowhere else. So the create form says what it does and
 * does not confer, and the list makes "holds no grants" a visible state rather
 * than a blank cell.
 *
 * There is no email field, deliberately. Username is the canonical identifier,
 * so an address identifies nobody; it is collected and verified on public
 * self-registration only, where the strangers are. The cost is real and is
 * stated on the form: an owner-issued account has no reset link, and a
 * forgotten password is fixed by the operator rotating it.
 */

import { useState } from "react";
import { Link } from "react-router-dom";

import { consoleApi, type AccountView } from "../../console-api.js";
import { consoleHref } from "./nav.js";
import { formatWhen, plural } from "./format.js";
import { useConsole, useConsoleLoad, useWriter } from "./session.js";
import { Alert, Empty, TextField } from "./ui.js";

export function AccountsScreen(): React.JSX.Element {
  const { basePath } = useConsole();
  const { result, reload } = useConsoleLoad("accounts", () =>
    consoleApi.listAccounts({ limit: 200 }),
  );
  const [creating, setCreating] = useState(false);

  return (
    <>
      <div className="wc-head">
        <h1>Accounts</h1>
        <div className="wc-head-actions">
          <button
            type="button"
            className="wc-btn"
            data-tone="primary"
            onClick={() => {
              setCreating((open) => !open);
            }}
            aria-expanded={creating}
          >
            {creating ? "Close the new-account form" : "New account"}
          </button>
        </div>
      </div>

      <p className="wc-lede">
        Every person who uses the estate is a row here, including the owner account. An account on
        its own confers nothing: it can sign in to Ward and reach no app at all until a grant is
        issued for one.
      </p>

      {creating ? (
        <NewAccountForm
          onCreated={() => {
            setCreating(false);
            reload();
          }}
        />
      ) : null}

      {result.state === "loading" ? <p className="wc-lede">Loading the account list…</p> : null}

      {result.state === "failed" ? (
        <Alert tone="error" title="The account list did not load" takeFocus>
          {result.message}
        </Alert>
      ) : null}

      {result.state === "ready" ? (
        result.data.accounts.length === 0 ? (
          <Empty title="No accounts yet">
            <p>
              Ward holds no accounts. The break-glass credential you are signed in with is not one —
              it has no row in this table by design.
            </p>
            <p>
              Create the owner account here: an ordinary account with explicit admin grants across
              the apps, which is what should be used day to day.
            </p>
          </Empty>
        ) : (
          <AccountTable
            accounts={result.data.accounts}
            total={result.data.total}
            basePath={basePath}
          />
        )
      ) : null}
    </>
  );
}

function AccountTable({
  accounts,
  total,
  basePath,
}: {
  accounts: AccountView[];
  total: number;
  basePath: string;
}): React.JSX.Element {
  return (
    <div className="wc-table-scroll">
      <table className="wc-table">
        <caption>
          {plural(total, "account", "accounts")}
          {accounts.length < total ? `, showing the first ${String(accounts.length)}` : ""}.
        </caption>
        <thead>
          <tr>
            <th scope="col">Username</th>
            <th scope="col">Subject</th>
            <th scope="col">State</th>
            <th scope="col">Created</th>
            <th scope="col">
              <span className="wc-sr">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((account) => (
            <tr key={account.subject}>
              <th scope="row">
                <Link to={consoleHref(basePath, { kind: "account", subject: account.subject })}>
                  {account.username}
                </Link>
              </th>
              <td>
                <span className="wc-id">{account.subject}</span>
              </td>
              <td>
                {account.disabled ? (
                  <span className="wc-state" data-state="disabled">
                    Disabled
                    {account.disabledAt === null ? "" : ` since ${formatWhen(account.disabledAt)}`}
                  </span>
                ) : (
                  <span className="wc-state">Active</span>
                )}
              </td>
              <td className="wc-when">
                <time dateTime={account.createdAt} title={account.createdAt}>
                  {formatWhen(account.createdAt)}
                </time>
              </td>
              <td>
                <Link
                  className="wc-btn"
                  to={consoleHref(basePath, { kind: "account", subject: account.subject })}
                >
                  Access and state
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Create an account: a username and a password, and nothing else.
 *
 * The password is held in local state for the length of the submit and cleared
 * on the way out. It is never put in a URL, never echoed by the API, and never
 * shown again — if it is lost before it reaches the person, the fix is to
 * rotate it on their account page, not to look it up.
 */
function NewAccountForm({ onCreated }: { onCreated: () => void }): React.JSX.Element {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [mismatch, setMismatch] = useState<string | undefined>(undefined);
  const writer = useWriter();

  async function submit(event: React.FormEvent): Promise<void> {
    event.preventDefault();

    if (password !== confirm) {
      // Checked here rather than server-side because Ward is never sent the
      // second copy: a typo in a password that will be read out over the phone
      // is the failure this catches, and it is not Ward's business.
      setMismatch("The two passwords do not match.");
      return;
    }
    setMismatch(undefined);

    const created = await writer.run(
      () => consoleApi.createAccount({ username, password }),
      (account) =>
        `Created ${account.username}. It holds no grants and can reach no app until one is issued.`,
    );

    setPassword("");
    setConfirm("");
    if (created) {
      setUsername("");
      onCreated();
    }
  }

  return (
    <section className="wc-panel">
      <h2>New account</h2>
      <p className="wc-panel-note">
        A username and a password. <strong>No email address</strong> — Ward collects one only on
        public self-registration, so an account created here has no reset link. If the password is
        forgotten, rotate it from the account&rsquo;s own page and tell the person out of band.
      </p>
      <p className="wc-panel-note">
        Creating an account grants nothing. To make this the owner account, create it and then issue
        one admin grant per app on its page; there is no wildcard.
      </p>

      {writer.error === undefined ? null : (
        <Alert tone="error" title="Ward refused the account" takeFocus>
          {writer.error}
        </Alert>
      )}

      <form
        className="wc-form"
        onSubmit={(event) => {
          void submit(event);
        }}
      >
        <TextField
          label="Username"
          name="username"
          value={username}
          onChange={setUsername}
          autoComplete="off"
          spellCheck={false}
          opaque
          required
          disabled={writer.busy}
          hint="Ward folds case and Unicode form before comparing, so Alice and alice are the same account."
        />
        <TextField
          label="Password"
          name="new-password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="new-password"
          required
          disabled={writer.busy}
          hint="At least 8 characters. It is never shown again — pass it on before you leave this page."
        />
        <TextField
          label="Password again"
          name="confirm-password"
          type="password"
          value={confirm}
          onChange={setConfirm}
          autoComplete="new-password"
          required
          disabled={writer.busy}
          error={mismatch}
        />
        <div className="wc-actions">
          <button type="submit" className="wc-btn" data-tone="primary" disabled={writer.busy}>
            {writer.busy ? "Creating…" : "Create account"}
          </button>
        </div>
      </form>
    </section>
  );
}
