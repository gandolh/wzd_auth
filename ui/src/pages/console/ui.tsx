/**
 * The console's small component vocabulary.
 *
 * Nothing here is a design flourish; each piece exists because one
 * accessibility or honesty rule has to hold on every screen and holding it by
 * hand in a dozen places means holding it in eleven.
 *
 * - **A field is a real `<label for>` plus an input**, with its hint and its
 *   error joined by `aria-describedby`. There is no placeholder-as-label
 *   anywhere in the console.
 * - **An error banner takes focus.** This is a keyboard surface for one
 *   operator under pressure; a message that appears below the fold, silently, is
 *   a message that was not delivered.
 * - **A destructive confirmation names what will happen**, in the same words as
 *   the result, and is a native `<dialog>` so Escape and the focus trap are the
 *   browser's problem rather than ours.
 * - **Every write announces its outcome** into a polite live region, including
 *   the outcome "nothing changed".
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";

/* ---------------------------------------------------------------------------
 * Fields
 * ------------------------------------------------------------------------ */

export interface TextFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: "text" | "password";
  /** Set it deliberately on every credential field. `off` is a choice too. */
  autoComplete?: string;
  hint?: ReactNode;
  error?: string;
  required?: boolean;
  disabled?: boolean;
  placeholder?: string;
  /** Renders the input in mono: the value is an identifier Ward stores verbatim. */
  opaque?: boolean;
  name?: string;
  list?: string;
  inputRef?: React.Ref<HTMLInputElement>;
  spellCheck?: boolean;
}

/** A labelled text or password input with its hint and error wired up. */
export function TextField({
  label,
  value,
  onChange,
  type = "text",
  autoComplete,
  hint,
  error,
  required,
  disabled,
  placeholder,
  opaque,
  name,
  list,
  inputRef,
  spellCheck,
}: TextFieldProps): React.JSX.Element {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [
    hint === undefined ? undefined : hintId,
    error === undefined ? undefined : errorId,
  ]
    .filter((part): part is string => part !== undefined)
    .join(" ");

  return (
    <p className="wc-field">
      <label htmlFor={id}>
        {label}
        {required === true ? " (required)" : ""}
      </label>
      <input
        id={id}
        name={name}
        type={type}
        value={value}
        onChange={(event) => {
          onChange(event.target.value);
        }}
        autoComplete={autoComplete}
        required={required}
        disabled={disabled}
        placeholder={placeholder}
        list={list}
        spellCheck={spellCheck}
        data-opaque={opaque === true ? "true" : undefined}
        aria-invalid={error === undefined ? undefined : true}
        aria-describedby={describedBy === "" ? undefined : describedBy}
        ref={inputRef}
      />
      {hint === undefined ? null : (
        <span className="wc-field-hint" id={hintId}>
          {hint}
        </span>
      )}
      {error === undefined ? null : (
        <span className="wc-field-error" id={errorId}>
          {error}
        </span>
      )}
    </p>
  );
}

/* ---------------------------------------------------------------------------
 * Messages
 * ------------------------------------------------------------------------ */

export interface AlertProps {
  tone: "error" | "notice" | "done";
  title?: string;
  children: ReactNode;
  /**
   * Move focus here when it appears. Set it for the error that follows a
   * submit; leave it off for a standing notice, which would steal focus from
   * the form on every render.
   */
  takeFocus?: boolean;
}

/**
 * A message about what just happened, or about what a screen cannot do.
 *
 * `role="alert"` on the failure tones so a screen reader interrupts, `status`
 * for a success — an assistive technology should not be made to interrupt for
 * good news. `tabIndex={-1}` makes the element focusable so `takeFocus` can put
 * the operator on the text rather than leaving them below it.
 */
export function Alert({ tone, title, children, takeFocus }: AlertProps): React.JSX.Element {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (takeFocus === true) ref.current?.focus();
  }, [takeFocus]);

  return (
    <div
      className="wc-alert"
      data-tone={tone}
      role={tone === "done" ? "status" : "alert"}
      tabIndex={-1}
      ref={ref}
    >
      {title === undefined ? null : <h2>{title}</h2>}
      <p>{children}</p>
    </div>
  );
}

/**
 * A polite live region plus the setter that fills it.
 *
 * Every mutation the console performs ends with a sentence here, including the
 * ones where the answer is that nothing changed. The API reports a no-op
 * honestly (`created:false`, `removed:0`, `changed:false`) and writes no audit
 * row for it, so the console says "already so" rather than dressing it as a
 * success the log will not corroborate.
 */
export function useAnnounce(): {
  announce: (message: string) => void;
  region: React.JSX.Element;
  latest: string;
} {
  const [message, setMessage] = useState("");
  const announce = useCallback((next: string) => {
    setMessage(next);
  }, []);
  return {
    announce,
    latest: message,
    region: (
      <div className="wc-sr" role="status" aria-live="polite">
        {message}
      </div>
    ),
  };
}

/* ---------------------------------------------------------------------------
 * Confirmation
 * ------------------------------------------------------------------------ */

export interface ConfirmProps {
  open: boolean;
  title: string;
  /** What will happen, in the words the result will use. Required. */
  children: ReactNode;
  confirmLabel: string;
  tone?: "primary" | "danger";
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * A modal confirmation for an action that changes authority.
 *
 * Native `<dialog>` with `showModal()`, which gives the focus trap, the
 * inertness of the page behind it and Escape-to-cancel from the platform
 * instead of from three hundred lines of our own. `onCancel` is intercepted so
 * Escape routes through the same path as the Cancel button, and so a busy
 * dialog cannot be dismissed out from under a request in flight.
 */
export function Confirm({
  open,
  title,
  children,
  confirmLabel,
  tone = "danger",
  busy,
  onConfirm,
  onCancel,
}: ConfirmProps): React.JSX.Element | null {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (dialog === null) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      className="wc-dialog"
      ref={ref}
      onCancel={(event) => {
        event.preventDefault();
        if (busy !== true) onCancel();
      }}
    >
      <h2>{title}</h2>
      {children}
      <div className="wc-dialog-actions">
        <button type="button" className="wc-btn" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
        <button
          type="button"
          className="wc-btn"
          data-tone={tone}
          onClick={onConfirm}
          disabled={busy}
        >
          {busy === true ? "Working…" : confirmLabel}
        </button>
      </div>
    </dialog>
  );
}

/* ---------------------------------------------------------------------------
 * Layout pieces
 * ------------------------------------------------------------------------ */

export function Panel({
  title,
  note,
  tone,
  children,
}: {
  title: string;
  note?: ReactNode;
  tone?: "danger" | "notice";
  children?: ReactNode;
}): React.JSX.Element {
  return (
    <section className="wc-panel" data-tone={tone}>
      <h2>{title}</h2>
      {note === undefined ? null : <p className="wc-panel-note">{note}</p>}
      {children}
    </section>
  );
}

/**
 * An empty state.
 *
 * A heading and a sentence, never a grey dash. The console's most consequential
 * empty state is an account with no grants — which is the *default* for every
 * account Ward creates, and is easy to mistake for a page that failed to load.
 * Saying so in words is the fix.
 */
export function Empty({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <div className="wc-empty">
      <h3>{title}</h3>
      {children}
    </div>
  );
}

/** An opaque value Ward stores verbatim: a subject, a slug, a role, an id. */
export function Id({ children }: { children: ReactNode }): React.JSX.Element {
  return <span className="wc-id">{children}</span>;
}

/* ---------------------------------------------------------------------------
 * Loading
 * ------------------------------------------------------------------------ */

export type Loadable<T> =
  | { state: "loading" }
  | { state: "ready"; data: T }
  /** `code` is Ward's error code where there was one, else `"unknown"`. */
  | { state: "failed"; message: string; code: string };

/**
 * Load something once per key, and reload it on demand.
 *
 * Deliberately not a cache. Every value on this surface is authority as it
 * stands right now, and a console that shows a stale grant is a console that
 * tells an operator someone's access was removed when it was not. `reload` is
 * called after every mutation for the same reason.
 *
 * A `401` is not handled here: it is handed to `onUnauthorized`, which drops the
 * whole console back to the login screen. A dead session is not a per-screen
 * error, and letting each screen render its own "unauthorized" message would
 * leave an operator clicking around a console that can no longer do anything.
 */
export function useLoadable<T>(
  /** Everything the load depends on, as one string. Change it to reload. */
  key: string,
  load: () => Promise<T>,
  onUnauthorized: () => void,
): { result: Loadable<T>; reload: () => void } {
  const [result, setResult] = useState<Loadable<T>>({ state: "loading" });
  const [nonce, setNonce] = useState(0);

  // `load` and `onUnauthorized` are ordinary closures a caller may recreate on
  // every render — deliberately not in the effect's own dependency array
  // below, because only `key` and `nonce` are meant to trigger a reload (see
  // the doc comment above). So the effect still needs the *latest* versions
  // of each without depending on them, which is what a ref is for; the write
  // just has to happen in an effect rather than during render, so it runs
  // after every commit instead of during it.
  const loadRef = useRef(load);
  useEffect(() => {
    loadRef.current = load;
  });
  const unauthorizedRef = useRef(onUnauthorized);
  useEffect(() => {
    unauthorizedRef.current = onUnauthorized;
  });

  // `key`/`nonce` changing means a reload started, and the screen should show
  // "loading" immediately rather than the previous result sitting there until
  // the effect below gets around to it — which is what a synchronous
  // `setState` in the effect's body would do, one render late and after a
  // paint. Comparing against the previous request and setting state
  // conditionally, during render, is React's own sanctioned shape for
  // resetting state when a dependency changes.
  const requestId = `${key}:${String(nonce)}`;
  const [loadedFor, setLoadedFor] = useState(requestId);
  if (loadedFor !== requestId) {
    setLoadedFor(requestId);
    setResult({ state: "loading" });
  }

  useEffect(() => {
    let live = true;
    loadRef.current().then(
      (data) => {
        if (live) setResult({ state: "ready", data });
      },
      (error: unknown) => {
        if (!live) return;
        if (isUnauthorized(error)) {
          unauthorizedRef.current();
          return;
        }
        setResult({ state: "failed", message: messageFor(error), code: codeFor(error) });
      },
    );
    return () => {
      live = false;
    };
  }, [key, nonce]);

  return {
    result,
    reload: useCallback(() => {
      setNonce((value) => value + 1);
    }, []),
  };
}

/** True for a `ConsoleApiError` carrying a 401, without importing the class. */
export function isUnauthorized(error: unknown): boolean {
  return (
    typeof error === "object" && error !== null && (error as { status?: unknown }).status === 401
  );
}

/** A `ConsoleApiError`'s `code`, without importing the class. */
export function codeFor(error: unknown): string {
  if (typeof error === "object" && error !== null) {
    const code: unknown = (error as { code?: unknown }).code;
    if (typeof code === "string" && code !== "") return code;
  }
  return "unknown";
}

/** A sentence for any thrown value. Never renders a stack or a raw object. */
export function messageFor(error: unknown): string {
  if (error instanceof Error && error.message !== "") return error.message;
  return "Something failed and Ward gave no reason. Check the service log.";
}
