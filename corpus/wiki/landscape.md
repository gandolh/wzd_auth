---
summary: The candidate answers researched on 2026-09-01 — off-the-shelf identity providers from Keycloak down to Pocket ID, the forward-auth gateways, and building wzd_auth as a small owned service — with what each one costs against this estate specifically.
updated: 2026-09-01
---

# Landscape — what could play this role

Researched 2026-09-01. **Nothing here is chosen yet**; the choice is gated on
the questions in [open-questions.md](./open-questions.md). Read
[estate.md](./estate.md) first — several of these options are ruled in or out by
the one-origin topology, not by their own merits.

## Three families, not one list

The options are not interchangeable. They answer different questions.

### 1. Forward-auth gateways

The proxy asks a sidecar "is this request allowed?" before it reaches the app.
The app itself learns the user from injected headers (`Remote-User`,
`Remote-Groups`) and does no auth work at all.

- **Authelia** — the reference. Under 20 MB of container, typically under
  30–50 MB of RAM. Integrates with Caddy through the `forward_auth` directive
  against `/api/authz/forward-auth`. Its OIDC *provider* half is still a beta
  feature (stage 7 of 8 as of v4.39) though OpenID Certified for the Basic /
  Implicit / Hybrid / Form Post / Config profiles.
- **Tinyauth** — smaller still, and as of 2026 also formally OIDC-conformant.

**The catch for this estate:** forward-auth injects headers at the proxy. On
*one origin with sub-paths*, Caddy can gate `/atrium/*` and `/newspapper/*`
independently, so this genuinely works. But header-injected identity means the
app must trust a header, which is only safe while nothing can reach the app
except through Caddy — true here (pm2 services bind loopback), but it is a
standing invariant somebody can break with one deploy edit. It also does
nothing for the **WebSocket** (imbatranimOS) and **cookie-less media fetch**
(atrium `?token=`, newspapper `/uploads/*`) shapes.

### 2. Full OIDC identity providers

The app becomes a relying party: redirect to the IdP, get a code, exchange it
for tokens, map the subject to a local user row.

- **Pocket ID** — Go + SQLite, ~30 MB, OpenID Certified across three profiles
  (broader certified coverage than Zitadel's registry entry). **Passkey-only**:
  no passwords at all, with one-time login codes as the fallback when a device
  is unavailable. Has LDAP sync, groups, audit logs, a REST API, and 80+
  documented service integrations. Widely reported as trivial to run.
- **Zitadel** — Go, lean, fast (login portal ~100 ms), scales horizontally,
  strong multi-tenant isolation. Heavier than Pocket ID; overkill without
  tenants.
- **Authentik** — the most flexible: OIDC, OAuth2, SAML, LDAP, proxy mode,
  custom flows, admin UI, impersonation. **Requires PostgreSQL and Redis**,
  which is real infrastructure on a single shared VPS that currently runs
  nothing but Caddy, pm2 and SQLite files.
- **Keycloak** — the enterprise default. Java, heavy, and far past what this
  estate needs.
- **Kanidm** — Rust, correctness-first, light. Less ecosystem than the above.

**The catch for this estate:** OIDC's whole value is working *across* origins
and *across* trust boundaries. Here there is one origin and one owner. Adopting
it buys a redirect dance, a discovery document and token plumbing in six apps to
solve a problem the topology does not have — unless the goal is future
subdomains, third-party apps, or passkeys done properly (see the passkey note
below).

### 3. Build `wzd_auth` as an owned service

A small Fastify + SQLite service on the VPS, deployed like any other pm2 app,
owning `users` / `sessions` and issuing **one HttpOnly cookie at `Path=/` on
`gandolh.ro`**. Every app validates it — either by calling
`GET /wzd-auth/session` or by verifying a signed token locally.

- Cross-app SSO falls out of the single origin for free: log in once, the cookie
  is already attached everywhere.
- It absorbs both existing shapes without a fight: atrium's opaque revocable
  server sessions are the model, and the cookie transport is newspapper's,
  which also retires atrium's `?token=` query-string workaround.
- It is roughly the code that **already exists twice** in this repo estate —
  the hard parts (scrypt/argon2, timing-safe compare, IP-keyed lockout, dummy
  hash on unknown user, cookie `Secure` logic) are all written and tested in
  atrium and newspapper today.
- The cost is that it is bespoke: no certification, no ecosystem integrations,
  no passkeys unless written, and every future app is a client of something only
  this estate understands.

## The passkey question cuts across all three

Pocket ID's passkey-only stance is either the single best feature here or a
blocker, and which one depends entirely on who the users are. Atrium's D35 was
written around a **shared household tablet** where switching identity has to
cost one tap. Passkeys are per-device credentials; a shared tablet with several
household members is the scenario they fit worst. Conversely, for one owner with
a phone and a laptop, passkeys remove the password problem entirely.

## What the research does not settle

Every source consulted compares these tools on *homelab* terms — gating
off-the-shelf apps (Jellyfin, Gitea, Nextcloud) that already speak OIDC. This
estate is the opposite case: **six apps whose auth we wrote ourselves and can
change**. That inverts the usual trade — the integration cost that normally
argues *for* a standard IdP is the cost we would be *creating*, and the
"but then you own it" cost of a bespoke service is one already paid twice.

Sources:
[Cerbos — Authelia vs Authentik 2026](https://www.cerbos.dev/blog/authelia-vs-authentik-2026-idp) ·
[Authelia OIDC roadmap](https://www.authelia.com/roadmap/active/openid-connect-1.0-provider/) ·
[Caddy `forward_auth`](https://caddyserver.com/docs/caddyfile/directives/forward_auth) ·
[Pocket ID](https://github.com/pocket-id/pocket-id) ·
[bex.co — OIDC conformance at 30 MB](https://bex.co/blog/2026/08/06/pocket-id-tinyauth-oidc-certification) ·
[prohomelab SSO comparison](https://prohomelab.com/en/posts/sso-comparison/) ·
[Curity — OAuth and cookies in browser-based apps](https://curity.io/resources/learn/oauth-cookie-best-practices/)
