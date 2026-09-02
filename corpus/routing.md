# Routing

Which layer answers which question, and how work is picked up. Useful to anyone
— or any agent — starting cold.

The service is called **Ward**. `wzd_auth` is the repo's working name and is
retired — see [wiki/decisions.md](wiki/decisions.md).

**The design is settled** — six rounds of grilling, twenty decisions, sixteen
briefs. What is missing is code. Read the decisions pages before
proposing anything; most of the obvious alternatives were considered and
rejected there for recorded reasons. Proposing an implementation before
[wiki/open-questions.md](wiki/open-questions.md) is empty is jumping the queue.

## Intent

| The request | Route to |
|---|---|
| "add a todo", "remember to…" | a file in [todos/](todos/) |
| "let's build X", "work on brief NN" | a numbered spec in [briefs/todo/](briefs/todo/) |
| "what does the wiki say about X" | [index.md](index.md), then at most 2–3 wiki pages |
| "what should we use for auth" | [wiki/landscape.md](wiki/landscape.md) — then note it is **not decided** |
| "how does atrium/newspapper do auth today" | [wiki/estate.md](wiki/estate.md) |
| "why is it done this way" | one of five: [wiki/decisions.md](wiki/decisions.md) (topology, ownership, UI shape, naming) · [wiki/decisions-accounts.md](wiki/decisions-accounts.md) (registration, grants, identifier, the prune) · [wiki/decisions-tokens.md](wiki/decisions-tokens.md) (sessions, tokens, revocation) · [wiki/decisions-admin.md](wiki/decisions-admin.md) (superuser vs owner account) · [wiki/decisions-implementation.md](wiki/decisions-implementation.md) (driver, hashing, bind address — the calls made while building) |
| "why not just a JWT denylist" | [wiki/decisions-tokens.md](wiki/decisions-tokens.md) — answered, do not re-derive |
| "what's left to decide" | [wiki/open-questions.md](wiki/open-questions.md) |
| "what's the state of things" | [wiki/status.md](wiki/status.md) |
| "what do we call this" | [wiki/glossary.md](wiki/glossary.md) — in particular **superuser** vs **owner account**, which are not the same thing |

## Knowledge routing

| Question shape | Layer | Why |
|---|---|---|
| Why is it this way? What was rejected? | **wiki** — the four `decisions*.md` pages, [log.md](log.md) | The corpus is the *why*. |
| What's the current state? | **wiki** — [status.md](wiki/status.md) | The living dashboard. |
| How does app X authenticate today? | **wiki** — [estate.md](wiki/estate.md), then **verify in that repo** | The survey drifts; the other repo's code wins. |
| Is this option any good? | **wiki** — [landscape.md](wiki/landscape.md) | Desk research only — nothing here has been installed or measured. |
| Does this actually work? | **run it** | Nothing in the corpus is authoritative over behavior. |

## The other repos are the source of truth about themselves

This corpus summarizes auth in `atrium`, `newspapper`, `public-resource-map`,
`imbatranimOS` and `sports-app`. Those summaries are **copies**, and copies go
stale. Before relying on one, check the source — in particular
`atrium/corpus/wiki/decisions.md` (D30, D35) and
`newspapper/corpus/wiki/decisions-security.md`, both of which are actively
maintained and were grilled at the time.

## READ / SKIP

| | |
|---|---|
| **READ** | [index.md](index.md), then [wiki/estate.md](wiki/estate.md) — the topology finding there rules out several designs before they are proposed. |
| **SKIP** | `briefs/` and `todos/` wholesale — [status.md](wiki/status.md) has the state in one table. |
| **NEVER** | Treat a `ward.db` copy as a backup — WAL mode means the sidecars carry committed data; see [wiki/decisions-implementation.md](wiki/decisions-implementation.md). Use "admin" unqualified — [wiki/decisions-admin.md](wiki/decisions-admin.md) defines two privileged identities and they are not interchangeable. Contradict an inherited atrium decision silently. Say so out loud and carry a revision note back to that repo. |

## Working a brief

Sixteen briefs sit in [briefs/todo/](briefs/todo/), grouped into nine dependency
waves in [wiki/status.md](wiki/status.md). Briefs within a wave own disjoint
files and can run in parallel.

1. Read the brief in [briefs/todo/](briefs/todo/) — self-contained by design.
2. Respect its **Files you OWN** / **must NOT touch** contract.
3. When done: move it to [briefs/done/](briefs/done/) keeping its number, append
   an outcome note, add a [log.md](log.md) entry, fold what is durable into the
   wiki.
4. `bash corpus/lint.sh` must exit clean before committing corpus changes.
