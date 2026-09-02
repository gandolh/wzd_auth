---
summary: Nothing is open. The design was settled across six rounds of grilling on 2026-09-01 — kept as a page so the next open question has somewhere to land.
updated: 2026-09-01
---

# Open Questions

Only what is actually open. The moment one is answered, **delete it from this
page** — the history belongs in [../log.md](../log.md) and the outcome in the
decisions pages.

**Nothing is currently open.** The design was settled over six rounds on
2026-09-01; twenty decisions live across
[decisions.md](./decisions.md),
[decisions-accounts.md](./decisions-accounts.md),
[decisions-tokens.md](./decisions-tokens.md) and
[decisions-admin.md](./decisions-admin.md).

An empty page here is the goal state, not a gap.

## One assumption worth correcting if it is wrong

The owner account's grants were recorded as **explicit, one per app, with no
wildcard** — read from "it should have all the permissions" plus the fails-safe
property the per-app registration flag was chosen for. If a genuine `*:admin`
wildcard was meant, that is the line to change, in
[decisions-admin.md](./decisions-admin.md).

## Not open — deferred to briefs

Work, not decisions:

- **The cutover.** Take a database copy first, then prune, then recreate.
  Atrium's repo has the `backup-pre-brief35-*` precedent.
- Rollout order; EdDSA key rotation procedure.
- The repo rename `wzd_auth` → `ward`, the `vps-deploy` entry, the `/ward-api`
  and `/ward` Caddy routes.
- UI stack — Vite + React, as the estate's other SPAs. prm already ships
  `reset_token` and `verification_token`; crib the email flow rather than
  inventing it.

## Not ours

- **Newspapper's now-exposed calls** — public `/uploads/*` and the IP-keyed
  lockout. Ward replaces its cookie; those two need a revision note in
  newspapper's own corpus.
- **Atrium's `HOST=0.0.0.0`** — binds all interfaces, so "Caddy is the only way
  in" rests on the firewall alone.
