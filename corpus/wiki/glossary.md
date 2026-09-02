---
summary: The vocabulary — one canonical definition per term wzd_auth uses in a particular way, and the synonyms each displaces. Terms whose meaning is still being grilled are marked provisional.
updated: 2026-09-01
---

# Glossary

One definition per term. Definitions only — no implementation detail. When a
term is defined, split or renamed, it is recorded here in the same session.

`_Avoid_` is the load-bearing half: it names the synonyms the term displaces,
which is what actually stops the drift.

## Estate
The set of side projects deployed from `vps-deploy` onto the shared Caddy VPS —
currently seventeen, of which six have or will have identity. The unit
wzd_auth serves. Surveyed in [estate.md](./estate.md).
_Avoid_: "the projects", "the apps", "the monorepo" (there is no monorepo — each
project is its own repo).

## Origin
Scheme + host + port, in the browser's sense: `https://gandolh.ro`. **The whole
estate is one origin**; the per-project `/atrium`, `/trips` and so on are paths
*within* it, and paths are not a security boundary.
_Avoid_: using "site", "domain" or "app" when the browser's isolation rule is
what matters — those three all blur the distinction that decides whether a
cookie is shared.

## Account
The unit a credential authenticates and the security boundary — inherited from
atrium D30. One account, one password, one set of sessions.
_Avoid_: "user" when the boundary is what is meant. See **Person** below.

## Profile
An identity *inside* an account, switchable with no password (atrium D35). A
household member, not a permission. **Atrium-local**: wzd_auth does not know
profiles exist, and no other app is obliged to have them.
_Avoid_: "sub-user", "child account", "role". A profile grants nothing.

## Person
A human being. Used only where the distinction from **Account** and **Profile**
is the point — one person may hold several accounts, and one account may be used
by several people.
_Avoid_: "user", which in this estate has meant a database row, a household
member and a human being in three different repos.

## Subject
The stable, opaque identifier wzd_auth gives an **account**, and the only thing
apps store to mean "this person". It is **the contract** between the identity
service and every app: stable forever, never recycled, unaffected by a username
change. An app's rows are keyed on it and outlive everything else about the
account.
_Avoid_: "user id" — every app already has one of those, meaning its own local
row. The whole point of a separate word is that the two are different numbers.

## Session
Proof that an account authenticated, held by the client and presented on each
request. **Whose shape is undecided**: atrium's is opaque, server-stored and
revocable; newspapper's is a stateless signed cookie that cannot be revoked
before it expires. Q4's downstream.
_Avoid_: "token" and "cookie" as synonyms for it — those are *transports* a
session can travel in, and this estate currently uses three (Bearer header,
query string, cookie).

## Grant
A `(subject, app, role)` triple held by Ward: this person may use this app, at
this role. **The security boundary of the estate.** Without a grant for an app,
holding a valid Ward account gives no access to it whatsoever.
_Avoid_: "permission" and "role" used alone. A role is one *field* of a grant,
and Ward stores role strings **opaquely** — it never interprets what a role may
do, which stays each app's business. There is **no wildcard grant**: even the
owner account holds six explicit rows, so a newly-added app is reachable by
nobody until someone says otherwise.

## Superuser
The break-glass credential in Ward's `.env`. **Has no account row**, no subject
and no grants — so it can administer Ward's console and reach **nothing else**.
Its session is never a JWT. Used when something is broken.
_Avoid_: "admin" and "the admin account", both of which mean the **Owner
account** below. Conflating the two is the specific mistake
[decisions-admin.md](./decisions-admin.md) exists to prevent.

## Owner account
An ordinary Ward account holding explicit admin grants across every app. The
daily driver — what actually runs atrium, newspapper and the rest. Created
through the console by the superuser at cutover, and revocable, rotatable and
auditable like any other account, which is exactly what the superuser is not.
_Avoid_: "superuser", "root". It has no special powers in Ward itself; it just
holds a lot of grants.

## Access token
The short-lived signed JWT in the session cookie. Proves *who*. Verified locally
by each app with Ward's public key; never checked against a denylist, and
deliberately carries **no permissions** — a token minted before a grant changed
would otherwise carry stale authority for its whole lifetime.
_Avoid_: "the JWT" unqualified — the refresh token is not one, and the
difference is the entire design.

## Refresh token
The long-lived, **opaque** credential that buys a new access token. It is a
**row**, so revoking it is deleting it. Rotated on every use; presenting an
already-spent one is a theft signal that kills the whole family.
_Avoid_: "session id" — it is not presented on ordinary requests, only at the
refresh endpoint.

## Introspection
An app asking Ward "is this session still live, and what are its grants?",
cached briefly per session. Establishes **liveness and authorization**, where
local signature checking establishes only authentication.
_Avoid_: "validation", which blurs the two halves — the signature is valid long
after the session is revoked.

## Forward auth
The pattern where the reverse proxy asks a sidecar to authorize a request before
it reaches the app, and passes identity down as injected headers. One of the
three candidate families in [landscape.md](./landscape.md).
_Avoid_: calling it SSO — it gates requests; it does not necessarily issue an
identity the app can reason about.

## Relying party
An app that delegates authentication to wzd_auth rather than performing it. What
atrium and newspapper would become.
_Avoid_: "client", which in an OAuth context means something narrower and in a
frontend context means the browser bundle.
