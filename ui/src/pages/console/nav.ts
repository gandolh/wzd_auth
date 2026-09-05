/**
 * Where in the console we are, derived from the URL rather than from a nested
 * `<Routes>` block.
 *
 * ## Why this exists at all
 *
 * The contract between the two UI briefs is that brief 10 exports one
 * `<ConsoleRoutes />` element and brief 09's router mounts it under `/console`.
 * A descendant `<Routes>` with relative paths only matches deeper URLs when the
 * parent route was declared with a splat (`path="/console/*"`), and the
 * contract does not say that it was. Guessing wrong yields a console that
 * renders blank for every URL except its index — a failure that appears only
 * once the two briefs are integrated.
 *
 * Reading the pathname ourselves removes the guess. It works under
 * `path="/console/*"`, under `path="/console"` for the index, inside a layout
 * route, and even if brief 09 renders the element without a `Route` at all. The
 * only thing it needs from the router is `useLocation`.
 *
 * ## The `/ward` base
 *
 * Vite builds with `base: "/ward/"` and Caddy serves the SPA there, so the
 * browser's path is `/ward/console/accounts`. Whether `useLocation().pathname`
 * carries that prefix depends on brief 09's `basename`, which is theirs to set.
 * So the split is on the **first `console` segment** and the prefix before it is
 * kept and reused for every link — the console never assumes it is mounted at
 * the root, and never hard-codes `/ward`.
 */

/** Which console screen a URL names. */
export type ConsoleView =
  | { kind: "accounts" }
  | { kind: "account"; subject: string }
  | { kind: "apps" }
  | { kind: "app"; slug: string }
  | { kind: "audit" }
  | { kind: "unknown"; rest: string[] };

/** A pathname split into the prefix the console is mounted at and the view. */
export interface ConsoleLocation {
  /**
   * Everything up to and including the `console` segment, with no trailing
   * slash — `/console`, or `/ward/console`. Prefix every link with it.
   */
  basePath: string;
  view: ConsoleView;
}

/** Drop empty segments so `//console//apps/` parses the same as `/console/apps`. */
function segments(pathname: string): string[] {
  return pathname.split("/").filter((segment) => segment !== "");
}

/**
 * Parse a pathname into a mount prefix and a view.
 *
 * A path with no `console` segment is treated as the console index, because the
 * only way to render this component at all is for the parent router to have
 * decided the URL belongs to the console. Refusing to render in that case would
 * turn a mounting choice we do not control into a blank page.
 */
export function parseConsoleLocation(pathname: string): ConsoleLocation {
  const parts = segments(pathname);
  const at = parts.indexOf("console");
  const before = at === -1 ? parts : parts.slice(0, at);
  const rest = at === -1 ? [] : parts.slice(at + 1);
  const basePath = `/${[...before, "console"].join("/")}`;

  return { basePath, view: viewFor(rest) };
}

function viewFor(rest: string[]): ConsoleView {
  const [head, second, ...tail] = rest;

  if (head === undefined) return { kind: "accounts" };

  if (head === "accounts" && second === undefined) return { kind: "accounts" };
  if (head === "accounts" && second !== undefined && tail.length === 0) {
    return { kind: "account", subject: decodeURIComponent(second) };
  }

  if (head === "apps" && second === undefined) return { kind: "apps" };
  if (head === "apps" && second !== undefined && tail.length === 0) {
    return { kind: "app", slug: decodeURIComponent(second) };
  }

  if (head === "audit" && second === undefined) return { kind: "audit" };

  return { kind: "unknown", rest };
}

/** The href for a view, under a given mount prefix. The only link builder. */
export function consoleHref(basePath: string, view: ConsoleView): string {
  switch (view.kind) {
    case "accounts":
      return `${basePath}/accounts`;
    case "account":
      return `${basePath}/accounts/${encodeURIComponent(view.subject)}`;
    case "apps":
      return `${basePath}/apps`;
    case "app":
      return `${basePath}/apps/${encodeURIComponent(view.slug)}`;
    case "audit":
      return `${basePath}/audit`;
    case "unknown":
      return `${basePath}/accounts`;
  }
}

/** Which rail entry is current. `account` sits under `accounts`, and so on. */
export function railSectionFor(view: ConsoleView): "accounts" | "apps" | "audit" | null {
  switch (view.kind) {
    case "accounts":
    case "account":
      return "accounts";
    case "apps":
    case "app":
      return "apps";
    case "audit":
      return "audit";
    case "unknown":
      return null;
  }
}
