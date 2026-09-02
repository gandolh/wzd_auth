---
summary: The locked calls about accounts themselves — who may register and what registration confers, the grant model that replaced signup as the security boundary, the canonical identifier, per-app signup flags, email, passwords-for-now, and the full-prune cutover. Administration and privilege are in decisions-admin.md.
updated: 2026-09-01
---

# Decisions — accounts, registration and grants

Foundational scope calls (topology, ownership, the name) live in
[decisions.md](./decisions.md); session mechanics in
[decisions-tokens.md](./decisions-tokens.md); administration and privilege in
[decisions-admin.md](./decisions-admin.md). Same rule: do not reopen one without
an explicit revisit and a [../log.md](../log.md) entry.

## Accounts are for the owner and a small set of known people; no public signup
> **⚠ REVISED 2026-09-01 (Q12) — superseded by *Ward owns access grants*, below on this page.**
> Public signup **is** allowed. The property this decision was protecting —
> that a stranger cannot reach atrium — is now enforced at **authorization**
> rather than at **registration**. The reasoning below is kept because it is
> what the revision had to answer.

_2026-09-01, grilled Q2_ — The audience is the owner plus people he knows.
Accounts are created deliberately, not by strangers. This keeps atrium's D30
(operator-seeded, no self-registration) intact estate-wide.

**This contradicts `public-resource-map`, and that is a live conflict, not an
oversight.** prm ships a public `registerSchema` with `user`/`admin` roles and
`emailVerified` — a genuine public signup surface. One of the two has to give,
and which one is Q8 in [open-questions.md](./open-questions.md).

**Rejected: designing for public signup from the start.** Email verification,
abuse handling, account recovery and rate-limited registration are most of the
cost of an identity service, and letting one app's public surface set the
security model for the other five buys machinery nobody has asked for.

## Passwords only for now; passkeys stay additive and later
_2026-09-01, grilled Q7_ — The first cut authenticates with a password. Passkeys
are not ruled out; they are ruled *later*, and they will be an **alternative**
credential rather than a replacement.

**Rejected: passkey-only** (the Pocket ID model). Recorded because it is the
option that looks strictly more modern and will be proposed again. It fails on
one specific scenario the estate actually has: passkeys are **per-device**
credentials, and atrium's D35 was designed around a **shared household tablet**
where becoming a different person costs one tap. Passkey-only turns that into
"whose phone is nearby". It would also strand atrium's existing scrypt hashes,
which may otherwise port across untouched.

Adding passkeys later is cheap specifically because of the one-origin decision —
the WebAuthn relying-party ID is just `gandolh.ro`, with no per-app registration.

## Ward owns access grants; the security boundary moves from signup to authorization
_2026-09-01, grilled Q12; **revises the two decisions above**_ — Anyone may
register. **Registering grants almost nothing.** A grant is a
`(subject, app, role)` triple held by Ward, and without one for a given app, an
account cannot use that app at all.

Signup happens **at an app**, and confers only that app's baseline role — a
person self-registering at `public-resource-map` gets `prm:user` and nothing
else. Reaching atrium, or becoming `prm:admin`, requires a grant the owner
issues in Ward.

This resolves the collision between the no-public-signup decision and prm's
shipped public registration, and it resolves it in the better direction: the
thing actually worth protecting was never *who holds an account*, it was *who
can reach what*. Guarding registration only ever approximated that.

**Ward stores role strings opaquely and does not interpret them.** It knows
`(cristian, prm, admin)`; it does not know what an admin may do. That line is
load-bearing — putting the meaning of permissions in Ward means redeploying the
identity service every time any of six apps grows a capability.

**Rejected: prm stays outside Ward** (recommended at the time) — it leaves two
answers to "who is this person" standing, which is the problem this repo exists
to close. **Rejected: prm loses public registration** — it discards a real
public surface to preserve a rule that turned out to be the wrong rule.

**The cost, stated plainly:** public registration is now in scope, and with it
signup abuse and account recovery. Those are open — see
[open-questions.md](./open-questions.md).

## Username is the canonical identifier
_2026-09-01, grilled Q13_ — One `users` table keyed on username. Atrium and
newspapper already key on username, so two of the three existing stores migrate
unchanged.

**Rejected: email** (recommended at the time, on the grounds that it is globally
meaningful and the only basis for account recovery). The owner chose username.
**The consequence has to be carried, not forgotten:** `public-resource-map` keys
on email today, so its rows do not migrate mechanically, and account recovery
has no channel unless email is collected as an attribute anyway. Both land in
[open-questions.md](./open-questions.md).

## A grant carries a set of roles, not one
_2026-09-01, grilled Q15_ — One person may hold several roles in one app, so
every app's check is a set-membership test rather than an equality test.

**Rejected: exactly one role per app**, which is simpler and matches how prm's
`user`/`admin` works today. A set costs nothing to build now and avoids a data
migration the first time any app needs two roles at once — and with six apps,
that is a when rather than an if.

## Registration is open per app, and closed by default
_2026-09-01, grilled Q16_ — Ward holds a **flag per app** saying whether it
accepts public registration. `public-resource-map` is open; everything else is
closed. Signing up at an open app creates a Ward account and confers **that
app's baseline role only**.

**Rejected: registration open at Ward itself**, with the landing app deciding
the baseline grant. It is simpler and gives one signup page rather than several,
but it fails in the wrong direction: a new app would be reachable by strangers
until someone remembered to close it. The flag **fails safe** — a new app is
closed until explicitly opened, which is the property worth paying a little
complexity for.

## Email is optional, and required only on the public path
_2026-09-01, grilled Q17_ — Username is canonical, so email identifies nobody.
It is collected and **verified** on **public registration** only; accounts the
owner issues skip it entirely.

This puts the cost exactly where the strangers are. Public signup without email
has no way to tell a person from a script and no account-recovery channel;
requiring verification estate-wide would mean verifying your own address to use
atrium, which buys nothing.

**The cost is accepted:** a mail sender, a verification-token flow and a bounce
story are now in scope, and they are the single largest chunk of build cost in
this repo. **The gap is accepted too:** owner-issued accounts with no email have
**no recovery path** — a forgotten password is fixed by the owner reissuing it,
which is correct for an estate this size and would not be at any larger one.

## There is no migration; credentials are pruned and recreated in Ward
_2026-09-01_ — No hash porting, no dual-auth window, no username invented for
prm's email-keyed rows. Every existing credential store is emptied and every
account is recreated in Ward. This closes the last open question outright: prm's
rows do not need to migrate because they do not survive.

**Rejected: migrating atrium's scrypt hashes**, which would have worked — the
hashes are portable and atrium already keys on username. It is not worth the
code for an estate whose entire population is the owner and a few known people,
all of whom can simply be re-issued an account.

**⚠ REVISED 2026-09-01 (Q20): the prune takes everything, not just
credentials.** The owner was shown exactly what cascades and chose the clean
slate — atrium's profiles, reading progress, **notes and LaTeX projects** all
go, along with prm's favorites, notifications and tokens. Nothing is
re-anchored, because nothing survives to re-anchor. The paragraph below is kept
because it is the hazard that had to be understood before the choice was a real
one.

In atrium, `profiles.user_id` references `users` **ON DELETE CASCADE**,
and `reading_progress.profile_id` and `latex_projects.profile_id` cascade from
`profiles` in turn — so deleting a `users` row **destroys reading progress and
LaTeX projects**. `notes.profile_id` and `note_folders.profile_id` are
**ON DELETE RESTRICT**, which means such a delete would *fail* rather than take
them: an accidental safety net, and the only reason this is a caught hazard
rather than a lost afternoon.

**prm's shape is different and easier.** It is Drizzle with `ON DELETE no
action` on every foreign key, so deleting a `user` row *fails* until its
dependents go first — `favorite_event`, `favorite_place`, `notification`,
`reset_token`, `session`, `verification_token`. All of it is derived data;
there is no authored content in prm to lose.

**Execution note for whoever writes the cutover brief:** take a database copy
first. Atrium's repo already carries a `backup-pre-brief35-*` directory from the
last time a migration touched profile-scoped rows, so the precedent is the
project's own.
