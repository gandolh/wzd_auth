---
summary: The locked calls about how an app proves it is an app — the per-app service key every /introspect call carries, why the endpoint stopped being anonymous, why a rejected key is a 401 rather than an inactive session, why the key authenticates without scoping what it may see, and why Ward's own UI moved to GET /session instead of being exempted.
updated: 2026-09-06
---

# Decisions — app keys

Session and token mechanics are in [decisions-tokens.md](./decisions-tokens.md),
which is where introspection itself is decided; this page is only about **who is
allowed to ask**. Foundational scope calls are in
[decisions.md](./decisions.md).

## Every app authenticates to `/introspect` with its own key
_2026-09-06, built_ — `POST /introspect` requires `x-ward-app-key`: a
`wak_`-prefixed, 256-bit value Ward issues per app from the console and stores
only as `sha256`. An unkeyed caller is refused with `401
{"error":"invalid_app_key"}` before any signature verification or grant lookup.

**Why, when the token is already the credential.** The premise the original
"no client authentication, no rate limit" calls rested on — that the route is
unreachable from the internet — is false in the deployed topology. What the key
buys is three things the anonymous version could not have: an anonymous caller
is refused **before** Ward does cryptographic and database work on their
behalf; every call names the app that made it; and a leaked app configuration is
contained to one app and revoked in one console click, rather than being
indistinguishable from ordinary traffic.

**The key authenticates; it does not scope.** A keyed call still gets the whole
estate's grant map for the subject, exactly as before — sports-app learns your
atrium roles. Scoping the answer to the calling app is the obvious next move and
was **considered and declined for now**: it changes the response contract that
`@ward/client` and the app integrations are built against, and "who may ask" and
"what may they see" are two decisions. If it is revisited, the test that has to
change first is named in `api/src/routes/introspect.test.ts`.

**A bad key is a `401`, not `{"active":false}`.** The single exception to this
endpoint's one-answer rule, and the exception is the point: answering "not
active" to a misconfigured app would sign every one of that app's users out
simultaneously and silently, with a clean server log. `@ward/client` raises
`WardConfigurationError` — a **subclass** of `WardUnavailableError`, so every
app's existing fail-closed handling already catches it, while the message names
`WARD_APP_KEY`.

**The browser caller moved to `GET /session`.** Ward's own UI read `/introspect`
with the session cookie, and a key in a Vite bundle is a published string. The
tempting alternative — require a key only when there is no cookie — is
worthless and is recorded here so nobody re-proposes it: an attacker chooses
their own headers, so moving a token from a body into a `Cookie:` header is a
one-line change to a `curl` command, and a cookie-shaped exemption exempts
everybody. `/session` is safe unkeyed for a narrower reason: it reads the token
from the cookie and from nowhere else, so it grants no capability that setting
the cookie did not already grant.

**Still no rate limit**, and that conclusion is unchanged — a `429` here is read
by every app as "not live", so a limit takes the estate down rather than
degrading an attacker. What changed is that the surface is no longer anonymous,
so a limit *could* now be applied per key if one is ever wanted.

**Several live keys per app is deliberate.** Rotation is issue → deploy →
confirm the old key stopped being used → revoke. A one-key-per-app constraint
would force a window with no working key, which is an outage on every rotation.
`app_keys.last_used_at` exists to make "has it stopped" answerable, and is
stamped **at most hourly** so the estate's hot path is not also a write path.
