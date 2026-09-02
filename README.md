# Ward

One sign-in for every side project on the shared VPS.

Today [atrium](../atrium) and [newspapper](../newspapper) each own a complete,
separately-designed auth stack, and four more apps have grown their own. Ward
replaces all of them with a single identity, a single credential store, and a
single set of access grants.

The repo directory is still `wzd_auth` for now; the service itself is
**Ward**. See [corpus/wiki/overview.md](corpus/wiki/overview.md#naming) for
why.

## The settled shape

A Fastify + SQLite pm2 service at `/ward-api` on the shared origin, with a
Vite + React UI at `/ward`. It owns credentials, account identity and
**grants** — `(subject, app, roles)` triples saying who may use what. Each
app keeps its own per-user rows, keyed on an opaque **subject**.

## Status

**Design settled, build started.** Twenty decisions are locked across the
`corpus/wiki/decisions*.md` pages, nothing is left open, and sixteen briefs
are written across nine dependency waves. Wave 1 — the scaffold — is landing
now.

Start at [corpus/index.md](corpus/index.md):

- [corpus/wiki/overview.md](corpus/wiki/overview.md) — what Ward is and the
  settled shape, in a paragraph.
- [corpus/wiki/status.md](corpus/wiki/status.md) — the current snapshot: what
  is decided, what is written, what is built.
- [corpus/wiki/estate.md](corpus/wiki/estate.md) — what auth exists across the
  estate today, and the one-origin topology that constrains every option.
- [corpus/wiki/landscape.md](corpus/wiki/landscape.md) — the candidates that
  were considered: forward-auth gateways, OIDC providers, or an owned
  service.

`bash corpus/lint.sh` must exit clean before committing corpus changes.
