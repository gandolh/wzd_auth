import type { ReactNode } from "react";

/**
 * The page shell for every screen brief 09 owns.
 *
 * Three rows: the wordmark, the crossing, one line of small print. See
 * `ward.css` for why the crossing hangs off a rule on the left instead of
 * sitting in a centred card.
 *
 * The wordmark is the only place Ward names itself, and it is deliberately the
 * smallest type on the page. Somebody arriving here was on their way to Atrium
 * or Newspapper; the interruption is shorter if the page leads with where they
 * were going.
 *
 * It is a `<p>` and **not** a heading. A heading above the `h1` would make the
 * page's outline start with the service's name and demote what the page is
 * actually for, which is the same inversion the visual design avoids. The one
 * `h1` per page is the destination or the task.
 */
export function Threshold({
  children,
  wide = false,
  footer,
}: {
  children: ReactNode;
  /** The self-service page is read rather than crossed, so it gets more room. */
  wide?: boolean;
  /** One line of small print. Omitted rather than filled with something. */
  footer?: ReactNode;
}): React.JSX.Element {
  return (
    <div className="ward-threshold">
      <p className="ward-threshold__mark">Ward</p>
      <div className="ward-threshold__body">
        <main className={wide ? "ward-crossing ward-crossing--wide" : "ward-crossing"}>
          {children}
        </main>
      </div>
      {footer === undefined ? <div /> : <p className="ward-threshold__footer">{footer}</p>}
    </div>
  );
}
