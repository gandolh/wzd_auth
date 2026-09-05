import type { InputHTMLAttributes, Ref } from "react";

/**
 * A labelled text input, with the accessibility wiring done once.
 *
 * A login form is a keyboard-and-password-manager surface before it is
 * anything else, and every one of these is load-bearing rather than a nicety:
 *
 * - **A real `<label htmlFor>`.** Not a placeholder standing in for one, and
 *   not `aria-label`. It is what makes the label clickable, what a password
 *   manager reads to decide this is the username field, and what is left on
 *   screen once somebody has started typing.
 * - **`autoComplete` is required, not optional.** A password manager that
 *   cannot fill Ward's login page makes every app in the estate worse, because
 *   this is now the only place anybody types a password. The type is `string`
 *   with no default for exactly that reason: forgetting it has to be a
 *   compile error.
 * - **`aria-describedby` points at the hint and the error together**, in that
 *   order, so a screen reader reads the rule and then what went wrong rather
 *   than one or the other.
 * - **`aria-invalid` only when this field is what failed.** A wrong password
 *   is a form-level failure — the API will not say which half was wrong, and
 *   the UI must not guess — so `invalid` stays off for that and is used for
 *   "you left this empty" and "that is too short".
 */
export function Field({
  id,
  label,
  hint,
  error,
  inputRef,
  ...input
}: {
  id: string;
  label: string;
  /** A rule worth stating before somebody breaks it. */
  hint?: string;
  /** This field's own problem. Form-level errors belong in a `Notice`. */
  error?: string;
  inputRef?: Ref<HTMLInputElement>;
} & Omit<InputHTMLAttributes<HTMLInputElement>, "id" | "className"> & {
    autoComplete: string;
  }): React.JSX.Element {
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy =
    [hint === undefined ? undefined : hintId, error === undefined ? undefined : errorId]
      .filter((value): value is string => value !== undefined)
      .join(" ") || undefined;

  return (
    <div className="ward-field">
      <label htmlFor={id}>{label}</label>
      <input
        {...input}
        id={id}
        ref={inputRef}
        className="ward-input"
        aria-describedby={describedBy}
        aria-invalid={error === undefined ? undefined : true}
      />
      {hint !== undefined && (
        <span className="ward-field__hint" id={hintId}>
          {hint}
        </span>
      )}
      {error !== undefined && (
        <span className="ward-field__hint ward-field__hint--error" id={errorId}>
          {error}
        </span>
      )}
    </div>
  );
}
