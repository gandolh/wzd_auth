import { useEffect, useRef, type ReactNode } from "react";

export type NoticeTone = "error" | "wait" | "info";

/**
 * A form-level message: what went wrong, or what is true and worth knowing.
 *
 * ## Focus moves here on a failure, and only on a failure
 *
 * A sighted person sees the message appear; somebody using a screen reader or a
 * keyboard does not, and the submit button they just pressed is now three
 * elements below a message they have no reason to know exists. So an `error`
 * notice takes focus when it mounts. It is a `<div tabIndex={-1}>` rather than
 * anything clickable — reachable programmatically, absent from the tab order,
 * so tabbing forward from it lands back on the first field.
 *
 * `info` and `wait` do **not** take focus. They are not responses to a failed
 * action: they are context that was already true when the page loaded (an
 * unconfirmed address, a lockout still running down), and stealing focus for
 * something nobody asked about is the aggressive half of this pattern.
 *
 * ## The tone is not decoration
 *
 * `error` is a wrong password, which is an *ordinary* event and is styled as
 * ordinary — Ward's `--ward-danger` is reserved for destructive confirmations,
 * and a login form that flashes alarm colours at somebody's first typo is
 * telling them they did something wrong when they did something normal. `wait`
 * is the lockout: a state that ends by itself, so it reads as a clock rather
 * than as a refusal.
 */
export function Notice({
  tone,
  children,
  /**
   * `assertive` for something that has just happened and changes what to do
   * next; `polite` for something that was already true.
   */
  live,
}: {
  tone: NoticeTone;
  children: ReactNode;
  live?: "polite" | "assertive";
}): React.JSX.Element {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (tone === "error") ref.current?.focus();
  }, [tone]);

  return (
    <div
      ref={ref}
      className={`ward-notice ward-notice--${tone}`}
      // `alert` on an error so it is announced without waiting for a pause;
      // `status` otherwise. Both are set alongside `aria-live` rather than
      // relying on the implicit value, because the implicit politeness of
      // `status` is not honoured consistently.
      role={tone === "error" ? "alert" : "status"}
      aria-live={live ?? (tone === "error" ? "assertive" : "polite")}
      tabIndex={tone === "error" ? -1 : undefined}
    >
      {children}
    </div>
  );
}
