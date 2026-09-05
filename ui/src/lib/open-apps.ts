import { useEffect, useState } from "react";

import { listOpenApps, type OpenAppView } from "./api.js";
import { CAN_LIST_OPEN_APPS } from "./self-service.js";

/**
 * The apps open to public registration, fetched once per mount.
 *
 * Shared by `Login` (the "create an account" link) and `Register` (naming the
 * app and knowing it is closed before the form is filled), because both need
 * the same answer to the same question and neither should fetch it twice.
 *
 * `"unknown"` covers two cases on purpose: `CAN_LIST_OPEN_APPS` is off, or the
 * request failed. Both mean "this UI cannot say", and both callers already
 * have a correct fallback for that — render as if the flag were off, and let
 * `Register`'s own submit still catch `403 registration_closed`. `"loading"`
 * is distinct from `"unknown"` so a page does not flash "closed" for the
 * instant before a fast, successful fetch resolves.
 */
export type OpenApps = "loading" | "unknown" | readonly OpenAppView[];

export function useOpenApps(): OpenApps {
  const [state, setState] = useState<OpenApps>(CAN_LIST_OPEN_APPS ? "loading" : "unknown");

  useEffect(() => {
    if (!CAN_LIST_OPEN_APPS) return;
    let live = true;
    void listOpenApps().then(
      (apps) => {
        if (live) setState(apps);
      },
      () => {
        if (live) setState("unknown");
      },
    );
    return () => {
      live = false;
    };
  }, []);

  return state;
}
