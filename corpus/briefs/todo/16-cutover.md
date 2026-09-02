# Task 16 — The cutover: back up, prune, recreate

## Context

⚠ **This is the destructive brief.** The owner was shown exactly what cascades
and chose a clean slate
([decision](../../wiki/decisions-accounts.md)): every existing account and all
of its per-app data goes, and accounts are recreated in Ward.

**What that includes, concretely** — atrium's `profiles`, `reading_progress`,
**`notes`** and **`latex_projects`**, and prm's `favorite_event`,
`favorite_place`, `notification`, `reset_token`, `session` and
`verification_token`. Newspapper's single admin simply disappears; its posts are
not user-scoped.

**This runs last — after the integrations, not before them.** Do not start until
briefs 00–15 are done. Pruning before the apps can talk to Ward leaves the
estate with no accounts and no way in.

## Files you OWN

- `scripts/cutover/**` in this repo — the backup and prune scripts
- Nothing inside the other repos except by running these scripts

## Files you must NOT touch

Application source in atrium, newspapper or prm — briefs 13–15 change those.
This brief only moves data.

## What to do

1. **Back up first, and verify the backup opens.** Copy every affected database
   to a dated directory. Atrium's repo already carries a
   `backup-pre-brief35-*` directory from the last time a change touched
   profile-scoped rows — same convention, same reason. **A backup you have not
   opened is not a backup.**
2. **Prune in dependency order.** Atrium cascades from `users` but `notes` and
   `note_folders` are `ON DELETE RESTRICT` and will *block* the delete — that
   safety net is why this hazard was caught, and the script must clear them
   explicitly rather than being defeated by it. prm is `ON DELETE no action`
   throughout, so every dependent goes before `user`.
3. **Recreate in Ward, through the console** (brief 10): the owner account, then
   explicit admin grants **one per app — no wildcard**, then any other people.
4. **Register the six apps** with `public_registration` **off** for all of them
   except prm.
5. **Make the scripts refuse to run twice**, and refuse to run at all without a
   verified backup present. This script deletes a person's notes; it should be
   hard to fire by accident.
6. **Order within this brief:** back up → recreate the accounts and grants in
   Ward → confirm sign-in works across all six apps → *only then* prune. The
   prune is the last irreversible step, and by the time it runs the new world
   must already be proven working.

## Acceptance

- A dated backup exists for every affected database and each one opens and
  reports its row counts before anything is deleted.
- Re-running the prune is a no-op that says so.
- After cutover the owner account signs in once and reaches every app.
- No app contains a user row that Ward does not know about.
- The rollback path is written down and has been read by a human.
