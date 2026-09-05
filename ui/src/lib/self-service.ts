/**
 * The self-service gap, in one file.
 *
 * Brief 09 asks for three things on `/ward/account`. Ward's API supports one of
 * them. The other two need endpoints that **do not exist**, and this file is
 * where that is recorded so the UI can say so honestly instead of either
 * pretending or quietly dropping the feature.
 *
 * ## What exists
 *
 * - **See my own grants** — `POST /ward-api/introspect` returns
 *   `{ active, subject, username, grants }` for the caller's own cookie. Built,
 *   wired, working.
 * - **Sign out of this device** — `POST /ward-api/logout` revokes the presented
 *   token's family and leaves the person's other devices alone. Built, wired,
 *   working. Note that it is the *opposite* of what point 5 of the brief asks
 *   for and cannot be made to do it: it kills this family, deliberately.
 *
 * ## What does not exist
 *
 * Neither of the two below can be faked from the console routes, and it is
 * important to say why rather than just that. `POST /console/accounts/:subject/password`
 * looks like the missing password endpoint and is not: it sits behind
 * `requireConsoleSession`, so an ordinary person's browser gets a `401`, and
 * the only way to make it succeed would be to put the break-glass superuser
 * credential — the one plaintext, unrotatable credential in the estate — into
 * a person's browser. It also takes no current password, which is the entire
 * security property a self-service change has and an operator override
 * deliberately does not.
 *
 * So the two flags below are `false`, the UI states the gap in plain words
 * where the control would be, and turning each one on is a one-line change here
 * once the endpoint lands.
 */

/**
 * **Missing: `POST /ward-api/account/password`.**
 *
 * What it would take:
 * - Authenticate from the `ward_session` cookie — same read `/introspect`
 *   does, then `resolveSession` for liveness, so a revoked session cannot
 *   change a password.
 * - Body `{ currentPassword, newPassword }`. Verify the current one with
 *   `verifyPassword` before anything else; a self-service change without it is
 *   an XSS or a borrowed laptop away from an account takeover with no recovery
 *   channel behind it.
 * - `hashPassword` the new one and surface `PasswordPolicyError.code`, so the
 *   UI can say `password_too_short` rather than a generic refusal.
 * - **Rotate the session**, which brief 09 asks for by name: revoke every
 *   refresh family for the subject and issue one fresh pair, so a password
 *   change signs out anybody who was holding a stolen cookie. That is the
 *   response to theft that actually removes the attacker, and it is why this
 *   endpoint and the one below are really one feature.
 * - Audit it. `session.password_changed` or similar — there is no audit action
 *   for a self-service change today, and an account credential changing with
 *   no row is the one event the console's trail should never miss.
 * - Rate-limit it on the address with its own `LockoutSurface` member. It
 *   takes a password as input, so it is a credential surface; brief 03's
 *   contract is explicit that a new one adds a member rather than borrowing
 *   `"login"`.
 */
export const CAN_CHANGE_OWN_PASSWORD: boolean = false;

/**
 * **Missing: `POST /ward-api/account/sessions/revoke-others`.**
 *
 * What it would take:
 * - Authenticate from the `ward_session` cookie, and read the **presented
 *   refresh token** to learn which family to spare. The access token's `sid`
 *   claim already names the family, so the family to keep is knowable without
 *   the refresh cookie — which matters, because `ward_refresh` is scoped
 *   `Path=/ward-api/refresh` and would not be sent to this path.
 * - Revoke every other live family for the subject. `revokeAllForSubject` and
 *   `revokeFamily` both exist in `api/src/db/refresh-tokens.ts`; the missing
 *   piece is "all but one", which is those two and a `WHERE family_id != ?`.
 * - Return how many sessions ended, because "it worked" is not reassuring to
 *   somebody who came here because they think their session was stolen, and
 *   "3 other sessions signed out" is.
 * - Audit it as its own action. This is the estate's only self-serve response
 *   to a suspected theft and it should leave a trail.
 * - Refuse a cross-site request the way `/logout` and `/refresh` do. It is a
 *   state-changing POST driven by a cookie, so it is CSRF-shaped, and the
 *   damage — signing somebody out of every other device — is exactly the sort
 *   of thing worth doing to a victim from another origin.
 *
 * **Why this one earns its place at all**, from the decision it comes from:
 * owner-issued accounts carry no verified email and therefore no recovery
 * channel, so this is the *only* self-serve move available to somebody who
 * thinks their session was stolen. Its absence is the most consequential gap in
 * this brief, and the honest reading is that the self-service page is currently
 * a grants viewer with a sign-out button.
 */
export const CAN_REVOKE_OTHER_SESSIONS: boolean = false;

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
 * **Missing: `GET /ward-api/account`.**
 *
 * `/introspect` answers with exactly four fields and a serialisation schema
 * that makes adding a fifth impossible by accident — deliberately, so that a
 * future change cannot put `password_hash` or `email` on the wire to six apps
 * that have no use for them. That is the right call for the endpoint every app
 * calls on every request, and it leaves this UI with **no way to read a
 * person's own email address or verification state** after a page reload.
 *
 * A separate cookie-authenticated `GET /ward-api/account` returning
 * `{ subject, username, email, emailVerified, createdAt }` is the shape that
 * fills it, and it is not the same endpoint wearing a flag.
 *
 * Until then `Account` shows the verification prompt only when this session
 * *just* signed in, because `POST /login` does return `emailVerified` and the
 * page can remember it in memory. On a reload the prompt is absent rather than
 * wrong, which is the correct direction to be incomplete in.
 */
export const CAN_READ_OWN_EMAIL: boolean = false;

/**
 * **Missing: `GET /ward-api/apps`** — a public list of apps that accept
 * registration.
 *
 * Not part of point 5, but the same shape of gap and it changes what this UI
 * can offer. `Register` is told which app it is signing somebody up for by
 * `?app=` in the URL, and it can name that app only because
 * `lib/estate.ts` carries a hard-coded display-name table — the real
 * `apps.name` is readable only through `GET /console/apps`, which is
 * superuser-only.
 *
 * Two things follow, both visible in the built UI:
 *
 * - **`Register` cannot tell somebody the app is closed until they submit.**
 *   `403 registration_closed` is a state, not an error — a fresh estate answers
 *   it to everything until the console creates an app — so the page renders it
 *   as a state. But it arrives *after* a form has been filled in, which is a
 *   worse moment to learn it than before.
 * - **`Login` carries no "create an account" link.** Most apps do not accept
 *   public registration, so a link from the estate's one login page would send
 *   most people to a form that refuses them.
 *
 * What it would take: a `GET` returning `[{ slug, name }]` for apps whose
 * `public_registration` is `1`. The query already exists —
 * `listPublicRegistrationApps` in `api/src/db/apps.ts` — and the response
 * exposes nothing an anonymous caller cannot already discover by trying
 * `POST /register` against a slug. It is public information by construction:
 * an app with public registration on is inviting strangers.
 */
export const CAN_LIST_OPEN_APPS: boolean = false;
