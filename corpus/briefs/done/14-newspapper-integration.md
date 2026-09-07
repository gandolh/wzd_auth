# Task 14 — Newspapper cuts over to Ward and leaves loopback

## Context

Two changes at once, and the second is the risky one:
[newspapper leaves loopback](../../wiki/decisions.md), which retires the premise
its whole security posture was written against. Its own
`decisions-security.md` says the loopback assumption is the first thing to
revisit on exposure. This is that revisit.

**Three of its calls are now internet-facing** and Ward only fixes one:

- ✅ The stateless 30-day HMAC cookie → replaced by Ward's session.
- ⚠️ **`/uploads/*` is deliberately public** — headless Chromium fetches images
  mid-render carrying no cookie. On loopback the exposure was bounded by 32 bits
  of ref entropy *and an unreachable port*. Only the entropy is left.
- ⚠️ **The IP-keyed lockout** was correct reasoning for a single-account app on
  localhost and now meets real traffic.

## Files you OWN

- `newspapper/api/src/auth/**` — mostly deletion
- `newspapper/api/src/routes/auth.ts`
- `newspapper/core/src/storage/users.ts` — delete
- `newspapper/ui/src/pages/Login.tsx`, `ui/src/components/auth/**`
- `newspapper/corpus/wiki/decisions-security.md` — the revision notes
- `newspapper/.env.example`

## Files you must NOT touch

The compiler, renderer, markup and editor. `output/**`.

## What to do

1. **Delete** `session.ts`, `password.ts`, `rateLimit.ts`, `secret.ts`, the
   `users` table and `SESSION_SECRET` / `ADMIN_USERNAME` / `ADMIN_PASSWORD`.
2. **Adopt `@ward/client`**, keeping the existing `config: { public: true }`
   route convention — it is a good pattern and the guarded/public split survives.
3. **Guard on `requireGrant("newspapper", …)`.**
4. **Decide `/uploads/*` deliberately, and write it down.** The render browser
   still carries no cookie. Either keep it public and accept a bounded exposure
   now that the port is reachable, or mint a short-lived render-scoped token —
   which the original decision rejected as "more machinery than a local
   single-user app earns", a reason that no longer holds. **This is the one real
   design call in the brief; do not let it default.**
5. **Revisit the lockout** now that it faces the internet. IP-keying still fails
   safe for a single account; the numbers may want revisiting.
6. **Add the newspapper block to the master Caddyfile** and a `vps-deploy`
   project, following brief 11's pattern.
7. **Update `decisions-security.md`** with a revision note on each of the three.

## Acceptance

- Rendering still works end to end — Chromium fetches its images and the JPEGs
  come out. This is the test that proves whatever you chose in step 4.
- No `SESSION_SECRET` anywhere; the app boots without it.
- Newspapper is reachable at `https://gandolh.ro/newspapper/` and gated.
- `decisions-security.md` carries three dated revision notes.
