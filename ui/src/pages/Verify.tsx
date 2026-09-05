import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { Notice } from "../components/Notice.js";
import { Threshold } from "../components/Threshold.js";
import { WardApiError, verifyEmail, type WardErrorCode } from "../lib/api.js";
import { onceByKey } from "../lib/once.js";

/**
 * `/ward/verify?token=…` — the landing page for a confirmation link.
 *
 * ## A single-use token and a double-invoked effect
 *
 * `GET /verify` **spends** the token: it marks the address confirmed and
 * deletes the row, so a second call answers `invalid_token`. `StrictMode`
 * double-invokes effects in development, which means the naive version of this
 * page reports "this link is not valid" for a link that worked perfectly the
 * first time, one millisecond earlier. React 18's release notes call this out
 * and it is exactly the class of bug `main.tsx` says StrictMode is on to
 * surface.
 *
 * So the outcome is memoised **per token at module level** by `lib/once.ts`,
 * and the second call gets the first call's promise. Module level rather than a
 * ref because the guarantee has to survive a remount, and keyed on the token
 * rather than a boolean so that a genuinely different link in the same page
 * session is still spent.
 *
 * ## What each outcome says
 *
 * `expired_token` is its own code because it is the one a person can act on —
 * except that **they cannot**, because there is no resend endpoint, by
 * decision. Brief 07 wrote the honest sentence and this page uses it: the
 * account works, the address is simply not confirmed. That is true rather than
 * consoling: `email_verified` gates no sign-in and no grant anywhere in Ward.
 * Presenting it as a dead end would be worse than the gap itself.
 *
 * Unknown, already-used and wrong-purpose all collapse to `invalid_token`, so
 * "I clicked the link twice" and "this was never a token" read the same. The
 * copy therefore has to cover both without guessing, which is why it leads with
 * the likely one.
 *
 * ## This page is the one the mail link actually visits
 *
 * `verificationLink` in `api/src/mail/templates.ts` points at
 * `/ward/verify?token=…` — this page, served by the UI bundle — rather than at
 * the API's own small server-rendered page. Both still exist:
 * `GET /ward-api/verify` performs the verification either way, and stays
 * reachable directly for a non-browser client, content-negotiated by
 * `Accept`. This page is simply the one a person actually lands on from their
 * inbox, which is why the copy above is written for that moment rather than
 * for a bare API response.
 */

type Outcome = "verified" | WardErrorCode;

/**
 * Spend a token, at most once per token for the life of the page.
 *
 * `onceByKey` is a separate, tested module rather than five lines here, because
 * it *is* the correctness argument for this page — see its header, and
 * `once.test.ts`, which models the single-use endpoint rather than merely
 * counting calls.
 */
const spend = onceByKey(async (token: string): Promise<Outcome> =>
  verifyEmail(token).then(
    (): Outcome => "verified",
    (error: unknown): Outcome => (error instanceof WardApiError ? error.code : "unexpected"),
  ),
);

export function Verify(): React.JSX.Element {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  // Only the fetched half of the outcome is state: an empty token needs no
  // round trip to know its answer, so that half is derived below rather than
  // seeded with a synchronous `setState` in the effect.
  const [fetched, setFetched] = useState<Outcome | undefined>();

  useEffect(() => {
    if (token === "") return;
    let live = true;
    void spend(token).then((result) => {
      if (live) setFetched(result);
    });
    return () => {
      live = false;
    };
  }, [token]);

  const outcome: Outcome | undefined = token === "" ? "invalid_request" : fetched;

  if (outcome === undefined) {
    return (
      <Threshold>
        <h1>Checking your link</h1>
        <p className="ward-lede">One moment.</p>
      </Threshold>
    );
  }

  if (outcome === "verified") {
    return (
      <Threshold
        footer={
          <Link className="ward-link" to="/login">
            Sign in
          </Link>
        }
      >
        <h1>Email confirmed</h1>
        <p className="ward-lede">
          That's your address confirmed. Nothing else to do here — sign in and carry on.
        </p>
      </Threshold>
    );
  }

  if (outcome === "expired_token") {
    return (
      <Threshold
        footer={
          <Link className="ward-link" to="/login">
            Sign in
          </Link>
        }
      >
        <h1>The link expired</h1>
        <p className="ward-lede">
          Confirmation links last 24 hours and this one is past that. Your account still works
          exactly as before — confirming an address doesn't unlock anything, so nothing is waiting
          on it.
        </p>
        <Notice tone="info">
          {/*
            Stated rather than hidden. Ward has no way to send a second link, and
            somebody who came here to fix something deserves to know that the
            thing they came to fix does not need fixing — and that if they do
            want the address on record, a person can set it.
          */}
          Ward can't send a replacement link yet. If you want the address on your account, ask
          whoever runs the estate to set it.
        </Notice>
      </Threshold>
    );
  }

  if (outcome === "unreachable") {
    return (
      <Threshold>
        <h1>Ward isn't answering</h1>
        <p className="ward-lede">
          The link is probably fine. Reload this page in a moment to try again.
        </p>
      </Threshold>
    );
  }

  return (
    <Threshold
      footer={
        <Link className="ward-link" to="/login">
          Sign in
        </Link>
      }
    >
      <h1>That link doesn't work</h1>
      <p className="ward-lede">
        Most likely it's already been used, in which case your address is confirmed and there's
        nothing left to do. Otherwise check it was copied in full — they're long.
      </p>
      <Notice tone="info">
        Either way your account works. Confirming an address doesn't unlock anything.
      </Notice>
    </Threshold>
  );
}
