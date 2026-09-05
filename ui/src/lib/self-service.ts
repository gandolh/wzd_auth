/**
 * The self-service gap, as it stood after brief 09, and closed.
 *
 * Brief 09 asked for three things on `/ward/account` and Ward's API supported
 * one of them; the other two needed endpoints that did not exist, and this
 * file recorded that so the UI could say so honestly instead of either
 * pretending or quietly dropping the feature. Those endpoints have since
 * landed — `POST /ward-api/account/password`,
 * `POST /ward-api/account/sessions/revoke-others`, `GET /ward-api/account`
 * and `GET /ward-api/apps` all exist now — and the four flags below are the
 * one-line switches that were promised turning each feature on.
 *
 * `CAN_RESEND_VERIFICATION` is the one flag that stays `false`, by decision:
 * see its own comment below.
 *
 * ## What has always worked
 *
 * - **See my own grants** — `POST /ward-api/introspect` returns
 *   `{ active, subject, username, grants }` for the caller's own cookie.
 * - **Sign out of this device** — `POST /ward-api/logout` revokes the
 *   presented token's family and leaves the person's other devices alone.
 *   Note that it is the *opposite* of "sign out my other devices" and cannot
 *   be made to do it: it kills this family, deliberately.
 */

/**
 * `POST /ward-api/account/password`. See `changeOwnPassword` in `lib/api.ts`
 * for the shape and the errors, and `Account.tsx`'s `ChangePassword` for the
 * form.
 *
 * The endpoint verifies the current password before anything else — a
 * self-service change that skipped that would be an account takeover one XSS
 * or one borrowed laptop away, with no recovery channel behind it — and it
 * **rotates the session**: every refresh family for the subject is revoked and
 * one fresh pair is issued to the caller, so the response's cookies keep this
 * browser signed in while every other holder of the old credential is signed
 * out. It runs on its **own lockout budget**, independent of `/login`'s, so a
 * person locked out here can still sign in — the UI's copy has to say that
 * rather than imply otherwise.
 */
export const CAN_CHANGE_OWN_PASSWORD: boolean = true;

/**
 * `POST /ward-api/account/sessions/revoke-others`. See `revokeOtherSessions`
 * in `lib/api.ts` and `Account.tsx`'s `OtherDevices`.
 *
 * The family to spare comes from the caller's own access token (its `sid`
 * claim), not from the refresh cookie — `ward_refresh` is scoped
 * `Path=/ward-api/refresh` and is simply never sent to this path. Every other
 * live family for the subject is revoked, and the response names how many:
 * "3 other sessions signed out" is reassuring in a way "done" is not, to
 * somebody who came here because they think their session was stolen.
 *
 * **Why this one earns its place at all**, from the decision it comes from:
 * owner-issued accounts carry no verified email and therefore no recovery
 * channel, so this is the *only* self-serve move available to somebody who
 * thinks their session was stolen. Before this flag turned on, the honest
 * reading was that the self-service page was a grants viewer with a sign-out
 * button.
 */
export const CAN_REVOKE_OTHER_SESSIONS: boolean = true;

/**
 * **Missing: no resend-verification endpoint, by decision in brief 07.**
 *
 * Recorded here rather than as a flag because there is nothing to turn on and
 * no control to hide: an expired verification link has no self-service
 * recovery, and the UI's job is to say so without presenting it as a dead end.
 * It survives because `email_verified` gates nothing — it blocks no sign-in and
 * no grant — so the true sentence is "your account works, the address just
 * isn't confirmed", and that is what `Verify` and `Account` say.
 */
export const CAN_RESEND_VERIFICATION: boolean = false;

/**
 * `GET /ward-api/account`. See `getAccount` in `lib/api.ts`.
 *
 * `/introspect` answers with exactly four fields and a serialisation schema
 * that makes adding a fifth impossible by accident — deliberately, so that a
 * future change cannot put `password_hash` or `email` on the wire to six apps
 * that have no use for them. That is the right call for the endpoint every app
 * calls on every request, and it left this UI with no way to read a person's
 * own email address or verification state after a page reload.
 *
 * `GET /ward-api/account` is the separate, cookie-authenticated endpoint that
 * fills that gap: `{ subject, username, email, emailVerified, createdAt }`,
 * with `email` `null` for an owner-issued account. `Account` now reads it
 * directly rather than remembering what `POST /login` said earlier in the
 * page's lifetime, so the verification prompt survives a reload instead of
 * disappearing on one.
 */
export const CAN_READ_OWN_EMAIL: boolean = true;

/**
 * `GET /ward-api/apps` — a public list of apps that accept registration. See
 * `listOpenApps` in `lib/api.ts`.
 *
 * Not part of point 5, but the same shape of gap and it changed what this UI
 * could offer. `Register` used to be told which app it was signing somebody up
 * for by `?app=` in the URL, and could only name that app from a hard-coded
 * display-name table in `lib/estate.ts` — the real `apps.name` was readable
 * only through `GET /console/apps`, which is superuser-only.
 *
 * Two things followed, and this flag fixes both:
 *
 * - **`Register` can now say an app is closed before a form is filled**,
 *   rather than only after a submit. `403 registration_closed` is still a
 *   state and not an error — a fresh estate answers it to everything until
 *   the console creates an app — but the fetched list lets the page know that
 *   up front.
 * - **`Login` can carry a "create an account" link** for the app it is about
 *   to hand somebody back to, when that app is one of the open ones. Most
 *   apps do not accept public registration, so the link is destination-aware
 *   rather than a blanket link that would send most people to a form that
 *   refuses them.
 *
 * The query behind the route is `listOpenApps` in `api/src/db/apps.ts`, and
 * the response exposes nothing an anonymous caller cannot already discover by
 * trying `POST /register` against a slug — an app with public registration on
 * is inviting strangers by construction.
 */
export const CAN_LIST_OPEN_APPS: boolean = true;
