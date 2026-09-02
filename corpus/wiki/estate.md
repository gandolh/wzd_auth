---
summary: What auth already exists across the side-project estate — atrium's accounts+profiles, newspapper's single-account cookie, the four other apps that grew their own, and the one-origin Caddy topology that constrains every option.
updated: 2026-09-01
---

# The estate as it stands

Surveyed 2026-09-01, before any decision. This page is **findings, not plans** —
it is the thing a centralized service has to absorb.

## The topology is the biggest constraint

Every deployed project is a **sub-path on one origin**: `https://gandolh.ro/<name>`,
served by a single Caddy instance from a master `Caddyfile` in the `vps-deploy`
repo (`infrastructure/Caddyfile`). There are no subdomains. `www` and the bare IP
`178.105.182.117` both redirect to the apex so there is exactly one canonical
origin.

That single fact removes most of the usual SSO difficulty and adds one risk:

- **A cookie set at `Path=/` on `gandolh.ro` is sent to every app automatically.**
  No redirect dance, no CORS, no token relay. Cross-app SSO is nearly free.
- **It also means there is no isolation between apps.** Same origin is same
  security context: any app's frontend JS can call any other app's API with the
  user's credentials attached, and an XSS in the most trivial static site
  (`/design-study`, `/saloon`) reaches atrium's API. Sub-paths do not sandbox.

A cookie also fixes an existing wart: atrium accepts `?token=` in the query
string purely because `<img>` cover tags cannot send an `Authorization` header.
Cookies ride on `<img>` requests for free.

## Atrium — the sophisticated one

Fastify + Knex over `better-sqlite3`. Deployed at `/atrium` (client) and
`/atrium-api` (pm2 service on `:8788`).

- **Accounts** are the security boundary. Operator-seeded via `scripts/seed.ts`;
  **no self-registration**. Passwords are **scrypt** with a per-password salt.
- **Sessions are opaque and server-stored** — a `sessions` table, a random
  32-byte token from `POST /auth/login`, revoked by `/auth/logout`.
- Presented as `Authorization: Bearer <token>` **or** `?token=<token>`.
- An app-wide `onRequest` guard rejects everything not allowlisted
  (`POST /auth/login`, `GET /auth/status`, `GET /health`, `OPTIONS`).
- Unknown usernames still spend a dummy scrypt hash, so timing does not leak
  account existence.
- **Profiles** (D35) are identities *inside* an account — a household model.
  Switching is free: no password, no PIN. The session row carries
  `active_profile_id`. Losing a profile is never an auth failure.
- The media library is **shared** across accounts; only identity, reading
  progress, notes and preferences are scoped.

Locked in `atrium/corpus/wiki/decisions.md` as D30 (accounts) and D35 (profiles).
Both are load-bearing and were grilled at the time — a central service either
honours them or must explicitly revise them.

## Newspapper — the loopback one

Fastify + `better-sqlite3`, three workspaces. **Not deployed yet** — absent from
`vps-deploy/projects/`, README describes localhost only — but it is going to the
VPS on the same domain (decided 2026-09-01), which retires the premise its
security decisions were written against. See
[decisions.md](./decisions.md#newspapper-leaves-loopback-which-retires-the-premise-under-its-security-decisions).

- **One account.** `ADMIN_USERNAME` / `ADMIN_PASSWORD` are read at *first boot
  only*, when the users table is empty.
- **Stateless HMAC cookie**, not a server session: `newspapper_session` =
  `v1.<userId>.<expiresAt>.<HMAC-SHA256>` keyed on `SESSION_SECRET`. HttpOnly,
  `SameSite=Lax`, `Path=/`, 30 days, `Secure` everywhere except loopback.
  Verified with `timingSafeEqual`. Rotating the secret signs everyone out.
- **Login lockout keyed on IP, never username** — deliberately, because with one
  account a username-keyed lockout lets any stranger lock the owner out.
- `POST /api/password` rotates the password and reissues the cookie.
- `/uploads/*` is deliberately public (headless Chromium fetches images
  mid-render and carries no cookie); `/api/*` and `/output/*` are guarded.

Its own `decisions-security.md` opens by saying every call there assumes
loopback and single-user, and that **the assumption is the first thing to
revisit if newspapper is ever exposed**. That moment has arrived: three of its
calls — public `/uploads/*`, a non-revocable 30-day cookie, and IP-keyed
lockout — now meet real internet traffic, and centralizing auth does not fix
any of them on its own.

## The two models disagree

| | Atrium | Newspapper |
|---|---|---|
| Accounts | many, operator-seeded | exactly one, first-boot seeded |
| Session | opaque, server-stored, revocable | stateless HMAC, not revocable |
| Transport | Bearer header + `?token=` | HttpOnly cookie |
| Hashing | scrypt | argon2/bcrypt via `password.ts` |
| Lockout | none | IP-keyed, 5 in 60s |
| Sub-identity | profiles (D35) | none |
| Deployed | yes, `/atrium` | not yet — going to the VPS |

Neither is wrong; they solve different problems. A shared service has to pick
one shape for each row, and the interesting rows are **session revocability**
and **whether profiles generalize**.

## Four more apps already grew their own

Centralizing for two apps only is under-counting the eventual load:

- **public-resource-map** (`/prm`, pm2 `:8790`) — email + password, `zod`
  schemas, **self-registration** (`registerSchema`), **roles** (`user` /
  `admin`), and `emailVerified`. The only app with a public signup surface, and
  it contradicts both atrium's operator-seeded-only rule and the no-public-signup
  decision. **A live conflict** — see Q8 in
  [open-questions.md](./open-questions.md).
- **imbatranimOS** (`/imbatranim-os`, Docker `:8080`) — a NestJS auth module
  with guards, a session service, a throttle service, a setup-token flow and
  **WebSocket auth** (`ws-auth.ts`). Its e2e suite covers auth, password and
  setup-token.
- **sports-app** (`/sports-app-api`, pm2 `:8794`) — a **shared secret** typed
  into the app's own settings screen, not a build-time URL. Its "session" is
  client-side persistence, not identity.
- **trips** (`/trips`) — static SPA, no auth today, but the repo is public and
  personal data is deliberately kept out of it.

WebSocket auth (imbatranimOS) and a no-header media fetch (atrium's `?token=`,
newspapper's public `/uploads/*`) are the two transport shapes that break naive
header-only designs.
