---
summary: What Ward is — one identity, one credential store and one set of access grants for every side project on the shared VPS — the settled shape in a paragraph, and how to pick up the thread.
updated: 2026-09-01
---

# Overview

**Ward is the one place a person signs in to any of the side projects on the
shared VPS.** Today atrium and newspapper each own a full, separately-designed
auth stack, and four more apps have grown their own. Ward replaces all of them
with one identity, one credential store, and one set of access grants.

The repo directory is still called `wzd_auth`; the service is **Ward**.

## The settled shape

A Fastify + SQLite pm2 service at `/ward-api` on the shared origin. It owns
credentials, account identity and **grants** — `(subject, app, roles)` triples
saying who may use what. Each app keeps its own per-user rows, keyed on an
opaque **subject**.

Login issues a 15-minute EdDSA-signed access token in a `Path=/` cookie, plus a
30-day opaque refresh row that rotates on every use. Apps verify the signature
locally to establish *who*, then ask Ward whether the session is live and what
it may do, caching that answer 30 seconds. Revoking anything is one write.

**Anyone may register; registering grants almost nothing.** The security
boundary is the grant, not the signup form.

## What the repo contains right now

A corpus, a README, and **the scaffold** — three npm workspaces, a fail-closed
environment contract, better-sqlite3 with a migration runner, and `GET /health`
on loopback (brief 00, landed 2026-09-02). No schema, no auth, no deploy yet.

The design was grilled to completion before any of it, because the expensive
mistakes here — identity model, session shape, whether the estate stays on one
origin — are all cheap to change on a wiki page and very costly in code.

## Where the thread is

1. [estate.md](./estate.md) — what already exists. Read this first; it is
   findings, not opinion, and several candidate designs are ruled out by the
   topology alone.
2. [landscape.md](./landscape.md) — the candidate answers, researched
   2026-09-01: forward-auth gateways, full OIDC providers, or an owned service.
3. The decisions — [decisions.md](./decisions.md) (topology, ownership, naming),
   [decisions-accounts.md](./decisions-accounts.md) (registration, grants,
   identifier) and [decisions-tokens.md](./decisions-tokens.md) (sessions,
   tokens, revocation). Most obvious alternatives were considered and rejected
   there, with reasons.
4. [decisions-implementation.md](./decisions-implementation.md) — the calls
   made *while building*: the storage driver, password hashing, the bind
   address, and why closing the database is a backup decision.
5. [open-questions.md](./open-questions.md) — deliberately empty. The design
   was settled across six rounds; the page is kept so the next open question
   has somewhere to land.

## The one thing worth knowing before reading anything else

Every project is a **sub-path on a single origin**, `https://gandolh.ro`. There
are no subdomains. That makes a shared session cookie nearly free and makes
isolation between apps impossible — the browser treats `/atrium` and
`/design-study` as the same security context. Most of the interesting design
tension in this repo traces back to that one fact.

## Naming

A ward is a protective enchantment on a threshold — it *is* access control, and
it keeps the estate's architectural naming (Atrium, Citadel, Hollow). The
working name `wzd_auth` was retired because `wzd` is *newspapper's markup file
extension*, which named the estate's identity service after one app's file
format.
