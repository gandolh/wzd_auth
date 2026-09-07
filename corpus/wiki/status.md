---
summary: Dated snapshot — Ward is feature-complete, app keys landed, and all five apps are cut over and green in their own repos. What remains is the deploy (newspapper has no stack, and the shared Caddyfile has no Ward entry) and the destructive prune; nothing has ever run against a real browser or a deployed Ward.
updated: 2026-09-06
---

# Status

_2026-09-06._

## Where things stand

**Waves 1–6 landed 2026-09-04. Ward is feature-complete as a service.** API,
`@ward/client`, and the UI: one central login page with the `?next=` handover,
public registration and verification, minimal self-service, and the superuser
console. **895 tests** across three workspaces.

**App keys landed 2026-09-06**, outside the wave plan. `POST /introspect` is no
longer anonymous — every call carries an `x-ward-app-key` issued per app from
the console — and Ward's own UI moved to a cookie-authenticated `GET /session`.
This revised a locked decision: "no client authentication" rested on the
endpoint being unreachable from the internet, and the deployed Caddy
configuration says otherwise. See
[decisions-app-keys.md](./decisions-app-keys.md).

**Wave 8 landed 2026-09-06: all five apps are cut over.** atrium, prm,
newspapper, imbatranimOS and sports-app each hand-write a Ward client against
[integrating.md](./integrating.md), hold their own app key, guard on a grant,
and have deleted their own credentials outright. Every suite is green in every
repo.

**What remains is the deploy and the prune.** Nothing has ever run against a
real browser or a deployed Ward — the shared Caddyfile still has no Ward entry —
and no destructive migration has been executed. Those are waves 7 and 9.

| Thread | State |
|---|---|
| Estate survey | **Done** — [estate.md](./estate.md) |
| Candidate research | **Done** — [landscape.md](./landscape.md) |
| Design grilling (6 rounds) | **Complete** 2026-09-01 |
| Decisions locked | **21** design, across five `decisions*.md` pages — [app keys](./decisions-app-keys.md) is the newest, and the only one taken after the build started — plus five engineering calls in [decisions-implementation.md](./decisions-implementation.md) |
| Open questions | **None** |
| Cutover | **Full prune** — every account and all its app data, then recreate |
| UI | **Central `/ward/login` + console + minimal self-service** |
| Name | **Ward** (repo still `wzd_auth`; rename pending) |
| Briefs written | **16** |
| Briefs done | **14** — 00–10 in [briefs/done/](../briefs/done/), plus 13 · 14 · 15 executed 2026-09-06 along with two unbriefed apps. **2 left**: 11 (deploy) and 16 (the prune) |
| App keys | **Built 2026-09-06**, unbriefed — schema, guard, console routes and panel. Consumed by all five apps; not yet deployed |
| Service code | **Complete.** API, `@ward/client`, and the UI at `/ward` — login, register, verify, self-service, and the console |
| Tests | **895** across three workspaces — 9 drive the real `buildApp()` end to end, now through the keyed `/introspect` |
| Deploy entry in `vps-deploy` | **Written, never run.** Ward plus four wired consumers; **newspapper has no stack** — see [the note below](#brief-11-is-already-written-in-vps-deploy) |
| Repo directory rename | **Deferred by the owner** — still `wzd_auth` on disk; `package.json` says `ward` |

## What is actually known

- The estate is **one origin**, `https://gandolh.ro`, sub-paths only. This
  constrains every candidate design and is the single most load-bearing fact.
- **Six apps** have or will have identity: atrium and newspapper (the two named
  in the request), plus public-resource-map, imbatranimOS, sports-app and
  eventually trips. Designing for two under-counts.
- Atrium and newspapper **disagreed on every row** of the auth model. Settled by
  the cutover: Ward's shape won each one, and each app's revision notes record
  what it gave up.
- Newspapper's **loopback premise is retired**. Its `/uploads/*` exposure was
  closed by intercepting the request rather than authorising it — see that
  repo's `decisions-security.md`.
- prm's public signup **collided with the no-public-signup decision** (Q8). That
  is what moved the estate's boundary from registration to authorization, and
  prm remains the only app with the flag on.

## Each app hand-writes its Ward client

**Decided 2026-09-06: there is no shared package in any app's dependencies.**
The apps are separate checkouts that `vps-deploy` rsyncs and `npm ci`s
independently, and every mechanism for sharing one package across them — a
registry, a committed tarball, a git dependency — costs more in build machinery
and deploy credentials than the ~200 lines it saves.

The cost is real and accepted with eyes open: **security code, written five
times**. [integrating.md](./integrating.md) is the mitigation — the contract all
five are written against — and `client/` stays as the tested reference
implementation (43 tests, shipped to nothing) so "what should this do" has one
answer. A change to any of the five behaviours goes there first, then to
`client/`, then to all five apps.

## The next move

**Wave 7 — the deploy.** `vps-deploy` now wires four of the five apps to Ward
(`ward.identityFor(app)`, which creates the deploy edge as a side effect of
reading the identity) and each holds a `WARD_APP_KEY` secret in its own
`secrets/<app>.env`. **newspapper has no stack there at all** and needs one,
plus a block in the shared Caddyfile that five live apps route through — a
mistake there is an outage for apps with nothing to do with Ward, so it wants a
person watching.

Then wave 9, which destroys every account in the estate.

**The honest gap, unchanged:** nothing has ever been deployed or run against a
real browser on the real origin. Every verification is `app.inject`, a local
socket, or a dev server whose proxy *imitates* Caddy. The cookie paths
(`/ward-api/refresh`, `/ward-api/console`) are the part most likely to be wrong
in a way no local test can show, because `handle_path` strips a prefix that
nothing local strips.

## Brief 11 is already written in vps-deploy

**Checked 2026-09-04, extended 2026-09-06.** Ward is `stacks/ward.ts`,
constructed first in `app.ts`; six of the brief's assumptions were verified
against what waves 1–6 built (the table is in [log.md](../log.md) under
2026-09-04). `identityFor(consumer)` now also hands the consumer a required
`WARD_APP_KEY` secret declared against that app's own stack, and four apps call
`useWard(ward.identityFor(app))` — so the deploy edge exists because the
identity was read, which is what the construct tree was refactored for.

**Written is not deployed**, and **newspapper still has no stack at all**.

## The waves

Briefs within a wave own disjoint files and can run in parallel. A wave is not
started until the one before it is verified.

| Wave | Briefs | What lands |
|---|---|---|
| ~~1–6~~ | ~~00–10~~ | ~~The service: schema, keys, login, introspection, grants, registration, client, UI, console~~ **DONE 2026-09-02 → 09-04** |
| ~~8~~ | ~~13 · 14 · 15 + 2 unbriefed~~ | ~~All five apps cut over~~ **DONE 2026-09-06** — ran ahead of wave 7 |
| 7 | 11 | Deploy — newspapper's stack, and Caddy routes |
| 9 | 16 | **The cutover** — back up, recreate, then prune |

Wave 8 ran before wave 7, inverting the plan. That is safe in the direction it
went — the app changes are all local and reversible, and none of them can be
*verified* until the deploy happens — but it means five apps are now written
against a service that has never answered a real request.

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

- ~~No `architecture.md`, `api.md` or `data.md`.~~ **Closed 2026-09-06** — not in
  the corpus but in `docs/`, a Starlight site at `/ward/docs`. Architecture, the
  HTTP surface, the data model, configuration and app keys are authored there
  against the code; this corpus is *rendered* into the same site rather than
  duplicated, and `.env.example` stays the canonical variable list.
- The research in [landscape.md](./landscape.md) is a survey of published
  comparisons, not hands-on evaluation. Nothing has been installed or measured.
  It documents a road not taken and should not be re-opened casually.
- **The integration gap is closed but narrow.** Nine tests drive the real
  `buildApp()` against a real database and a real key — happy paths and
  revocation, not the mail flow, not a browser, nothing concurrent beyond the
  one refresh race.
- **Two behaviours only the integration suite could see**, both recorded in
  code where they surfaced: the 10-second refresh race carve-out swallows a
  replay that fires too soon, and `session.refresh_denied` is effectively
  unreachable for the everyday disabled account because `/refresh` peeks the
  token's session before the rotation that would write the row.
- **Two review passes per wave have each found bugs the gates could not.** Every
  wave so far shipped at least one Critical or Important defect that typecheck,
  lint and a green suite all missed — the signing key being committable, the WAL
  checkpoint, the verify options bag, the multi-tab refresh. Budget for review as
  part of the work, not as a formality after it.
- Two briefs change **other repos'** locked decisions and owe revision notes
  there: 13 (atrium D30 and D35) and 14 (newspapper's three security calls).
