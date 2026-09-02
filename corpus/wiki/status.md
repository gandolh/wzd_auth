---
summary: Dated snapshot — the design is complete, sixteen briefs are written in nine dependency waves, and wave 1 (the scaffold) has landed. Nothing is decided that is not recorded.
updated: 2026-09-02
---

# Status

_2026-09-02._

## Where things stand

**Wave 1 landed 2026-09-02.** The repo holds a corpus, a README, and the
scaffold: three npm workspaces, a fail-closed environment contract,
better-sqlite3 with a static-import migration runner, and `GET /health` bound to
loopback. No schema, no auth, no UI, no deploy.

| Thread | State |
|---|---|
| Estate survey | **Done** — [estate.md](./estate.md) |
| Candidate research | **Done** — [landscape.md](./landscape.md) |
| Design grilling (6 rounds) | **Complete** 2026-09-01 |
| Decisions locked | **20** design, across four `decisions*.md` pages, plus five engineering calls in [decisions-implementation.md](./decisions-implementation.md) |
| Open questions | **None** |
| Cutover | **Full prune** — every account and all its app data, then recreate |
| UI | **Central `/ward/login` + console + minimal self-service** |
| Name | **Ward** (repo still `wzd_auth`; rename pending) |
| Briefs written | **16** |
| Briefs done | **1** — [00-scaffold](../briefs/done/00-scaffold.md); 15 left in [briefs/todo/](../briefs/todo/) |
| Service code | **The scaffold only** — `api/` boots and answers `/health` |
| Tests | **None.** No runner is wired; brief 01 should land one |
| Deploy entry in `vps-deploy` | **None** |
| Repo directory rename | **Deferred by the owner** — still `wzd_auth` on disk; `package.json` says `ward` |

## What is actually known

- The estate is **one origin**, `https://gandolh.ro`, sub-paths only. This
  constrains every candidate design and is the single most load-bearing fact.
- **Six apps** have or will have identity: atrium and newspapper (the two named
  in the request), plus public-resource-map, imbatranimOS, sports-app and
  eventually trips. Designing for two under-counts.
- Atrium and newspapper **disagree on every row** of the auth model —
  account count, session revocability, transport, hashing, lockout, sub-identity.
  A shared service picks one shape per row; the contested rows are session
  revocability and whether profiles generalize.
- Newspapper is **going to the VPS**, which retires the loopback premise its
  security decisions were written against and leaves three of its calls live on
  the public internet.
- The no-public-signup decision **collides with public-resource-map**, which
  ships self-registration. That conflict is Q8 and is the only place Round 1
  created a problem rather than closing one.

## The next move

**Build wave 2 — briefs 01 (schema) and 02 (signing keys).** They own disjoint
files and can run in parallel. Both consume contracts pinned by brief 00; the
outcome note on [00-scaffold](../briefs/done/00-scaffold.md) carries them, and
the one most likely to surprise is that **`getDb()` is async** — the dynamic
import is what keeps importing the db module side-effect-free.

Brief 01 should also land the test runner. Brief 00 verified its loopback bind
and fail-closed boot by hand, and nothing currently guards either against
regression.

## The waves

Briefs within a wave own disjoint files and can run in parallel. A wave is not
started until the one before it is verified.

| Wave | Briefs | What lands |
|---|---|---|
| ~~1~~ | ~~00~~ | ~~Scaffold, rename, env contract~~ **DONE 2026-09-02** |
| 2 | 01 · 02 | Schema; signing keys and JWKS |
| 3 | 03 · 06 | Login and refresh rotation; the superuser |
| 4 | 04 · 05 | Introspection; apps, grants and audit |
| 5 | 07 · 08 | Public registration and email; `@ward/client` |
| 6 | 09 · 10 | Login and self-service UI; the console |
| 7 | 11 | Deploy — vps-deploy project and Caddy routes |
| 8 | 13 · 14 · 15 | Atrium, newspapper and prm cut over |
| 9 | 16 | **The cutover** — back up, recreate, then prune |

**Wave 9 is destructive and runs last on purpose.** By the time the prune fires,
the new world has to be proven working — sign-in verified across all six apps.
Pruning earlier leaves the estate with no accounts and no way in.

⚠ **Brief 14 carries a real design call that must not default:** newspapper's
`/uploads/*` is public because headless Chromium fetches images carrying no
cookie. On loopback that exposure was bounded by ref entropy *and an unreachable
port*; on the internet only the entropy is left. The original decision rejected a
render-scoped token as "more machinery than a local single-user app earns" — a
reason that stops being true the moment the app is public.

⚠ **The cutover destroys data, by decision.** The owner was shown the cascade
and chose a clean slate: atrium's profiles, reading progress, **notes and LaTeX
projects**, and prm's favorites, notifications and tokens all go. Nothing has
been deleted yet — this happens at cutover, and the brief that does it must
**take a database copy first**. Atrium's repo already carries a
`backup-pre-brief35-*` directory from the last time a change touched
profile-scoped rows.

## The shape that was settled

Ward is a Fastify + SQLite pm2 service at `/ward-api` on the shared origin, with
a Vite + React UI at `/ward`. It owns credentials, account identity and **access
grants**; each app keeps its own rows keyed by an opaque **subject**.

Apps redirect to one central `/ward/login`. Login issues a 15-minute
EdDSA-signed access token in a `Path=/` cookie plus a 30-day opaque rotating
refresh row. Apps verify the signature locally, then ask Ward whether the
session is live and what it may do, caching that 30 seconds. Revoking is one
write.

Anyone may register at an app whose flag allows it, and registering grants
almost nothing — a `(subject, app, roles)` grant is the estate's actual security
boundary. Two privileged identities, deliberately not interchangeable: an
**environment-only superuser** that reaches the console and nothing else, and an
ordinary **owner account** holding explicit admin grants that runs the apps.

## What changed most

Q12 moved the estate's security boundary from **registration** to
**authorization**. Anyone may hold a Ward account; a grant is what lets them
reach anything. That revised two Round 1 decisions and pulled public signup —
with its abuse and recovery costs — into scope. It is the right shape, and it is
also the single largest source of remaining work.

## Known gaps in this corpus

- No `architecture.md`, `api.md` or `data.md`. Still correct: there is one
  route and no schema. Each should appear with the code that justifies it —
  `data.md` with brief 01, `api.md` once there is an API worth describing.
  Configuration is currently documented in `.env.example` itself, which names
  every variable and its reader; that is the right home while it fits on one
  page.
- The research in [landscape.md](./landscape.md) is a survey of published
  comparisons, not hands-on evaluation. Nothing has been installed or measured.
  It documents a road not taken and should not be re-opened casually.
- **One brief of sixteen is built, and nothing is tested.** The scaffold boots
  and was verified by hand, but no test runner is wired, so every property it
  established is unguarded against regression. Fifteen briefs — all of the auth
  itself — remain intent only.
- Two briefs change **other repos'** locked decisions and owe revision notes
  there: 13 (atrium D30 and D35) and 14 (newspapper's three security calls).
