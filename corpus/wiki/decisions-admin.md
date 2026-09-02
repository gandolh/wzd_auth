---
summary: The locked calls about administration and privilege — the environment-only break-glass superuser that can reach nothing but the console, the ordinary owner account that actually runs the apps, and the deliberate absence of any way to delegate console access.
updated: 2026-09-01
---

# Decisions — administration and privilege

Account and grant calls live in
[decisions-accounts.md](./decisions-accounts.md); foundational scope in
[decisions.md](./decisions.md); tokens in
[decisions-tokens.md](./decisions-tokens.md).

**The single most important thing on this page:** there are **two** privileged
identities and they are not interchangeable. Confusing them is the mistake this
page exists to prevent.

## The superuser lives only in the environment and has no account row
_2026-09-01, grilled Q23_ — `WARD_ADMIN_USERNAME` and `WARD_ADMIN_PASSWORD` in
Ward's `.env` are a **break-glass superuser**, not a seeded account. Ward's
database holds no row for them: no subject, no grants, nothing in the console's
account list, nothing to revoke.

**Rejected: seeding a first admin row on first boot** (newspapper's pattern, and
what was recorded here earlier the same day). It makes the first admin an
ordinary account that can be locked out, revoked, or deleted like any other —
which is exactly what a recovery mechanism must not be. **Also rejected:
`ward:admin` as an ordinary grant** gating the console, which is elegant —
Ward administered by the mechanism it administers — but leaves the estate one
bad revoke away from nobody being able to grant anything.

**The trade being accepted is explicit:** a live credential now sits in
plaintext on disk permanently, which is the precise thing first-boot-only
seeding existed to avoid. It is defensible *here* because this is break-glass
rather than a daily driver — the root-recovery pattern — and because it is the
only thing that still works when the database is empty, corrupted, or has had
its last admin removed.

**Consequence:** rotating the superuser password is a `.env` edit and a restart,
not a UI action. That is the correct friction for a credential of this kind.

## The superuser reaches the console and nothing else
_2026-09-01, grilled Q24/Q25_ — The superuser can administer Ward. It cannot
open atrium, newspapper, prm or anything else, and this needs no enforcement
code: **access in this estate is a grant, and the superuser has no grants.**
"Console only" is what the model already implies rather than a rule bolted on.

Its session is therefore a **distinct console session, never a JWT**. It has no
account row and so no subject to put in a `sub` claim.

**Rejected: a reserved sentinel subject** that apps are instructed to reject. It
works only while all six apps remember to implement the rejection — it fails on
discipline. A session that is not a JWT at all cannot accidentally satisfy an
app's ordinary auth check in the first place, so it fails safe.

**Rejected: a superuser bypass** making the credential implicitly all-powerful
everywhere. It is extra code whose only effect is to let a break-glass
credential read the library and the notes.

## The apps are run by an ordinary account, not by the superuser
_2026-09-01, grilled Q25_ — Day-to-day administration of the *apps* belongs to
a normal Ward account holding admin grants across them. It is created through
the console by the superuser at cutover, and it is the owner's daily driver.

This is the half that makes the superuser decision safe. Without it the
break-glass credential would inevitably become the everyday login — used from a
browser, on a phone, over a coffee-shop network — which is exactly what a
credential with no revocation, no rotation path and no audit trail must never
become. The superuser is used when something is broken; the owner account is
used the rest of the time.

**Its grants are explicit, one per app — there is no wildcard.** A `*:admin`
grant would mean a newly-added app is reachable the moment it exists, which
contradicts the fails-safe property the per-app registration flag was chosen
for. Six explicit grants are also six auditable rows.

## Console access cannot be delegated
_2026-09-01, grilled Q26_ — There is exactly one console credential and
therefore exactly one administrator, permanently. `ward:admin` as a grant was
already rejected; nothing replaces it.

**Recorded because it is a limit, not an oversight.** A second person cannot be
given the ability to issue grants without sharing the `.env` credential. That is
correct for an estate with one operator and would be wrong the moment there are
two — at which point this is the decision to revisit, and `ward:admin` with a
refuse-to-remove-the-last-one guard is the design that was set aside.
