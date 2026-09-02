# Task 11 — Deploy: the vps-deploy project and the Caddy routes

## Context

Ward is the seventeenth project on the shared VPS and follows the estate's
existing shape: a `deploy.ts` in `vps-deploy/projects/<name>/`, a pm2 service, a
static client, and routes in the **master** `infrastructure/Caddyfile`.

Read `vps-deploy/README.md` first. The master Caddyfile is the single source of
truth and most projects upload it wholesale, so a route added anywhere else is
lost the next time another project deploys.

## Files you OWN

- `vps-deploy/projects/ward/**` — `deploy.ts`, `.env.example`
- `vps-deploy/infrastructure/Caddyfile` — the two new blocks only
- `vps-deploy/README.md` — the project table row

## Files you must NOT touch

Any other project's block in the Caddyfile. Anything in the Ward repo itself.

## What to do

1. **Two routes**, following the `/atrium` + `/atrium-api` precedent exactly:
   - `handle_path /ward-api/*` → `reverse_proxy localhost:<port>`
   - `redir /ward /ward/ 308` + `handle_path /ward/*` serving the SPA with
     `try_files … /index.html`
   Pick a port not already taken — 8788, 8787, 8790, 8794 and 8080 are in use.
2. **`/ward-api/…` must never match `/ward/*`.** Path matching is literal and
   the character after the prefix must be `/`, which is what keeps the pair
   apart — the same reasoning the atrium block documents. Add a comment saying
   so, because this is the trap in the file.
3. **The service binds loopback.** Brief 00 defaults `HOST` to `127.0.0.1`;
   the deploy must not override it. Caddy is the only way in, and unlike
   atrium's `HOST=0.0.0.0` that should be true by configuration rather than by
   firewall.
4. **The signing key is not in the repo and not in `.env`.** It is a file on the
   server, created once, backed up, and never regenerated on deploy — a
   regenerated key signs the whole estate out. Document where it lives.
5. pm2 service named `ward-api`, restarting on boot like its siblings.
6. The SPA builds with the base path `/ward/`.

## Acceptance

- `https://gandolh.ro/ward/` serves the login page and `/ward-api/health`
  answers, both over the real certificate.
- Deploying any *other* project afterwards does not remove Ward's routes —
  verified by deploying one, which is the actual failure mode this file has.
- The API is unreachable on the VPS's public interface directly; only via Caddy.
- A redeploy leaves the signing key untouched and existing sessions alive.
