// Compile the typed JSON IR in diagrams/ into self-contained interactive HTML
// under public/diagrams/, using archify.
//
//   docs/diagrams/<name>.json  ──►  docs/public/diagrams/<name>.html
//
// ── Why the output is committed ────────────────────────────────────────────
//
// archify is an AGENT SKILL, installed per-machine under ~/.claude/skills (or
// ~/.agents/skills) — it is not an npm dependency and `npm ci` will not bring
// it. The docs build, though, runs wherever vps-deploy runs. So the rendered
// artifacts are committed, and this script REGENERATES them when archify is
// present and otherwise verifies that what is committed is still complete.
//
// That means a machine without the skill can build and deploy the docs, and a
// machine with it can change a diagram by editing the JSON — which is the part
// worth version-controlling, since the HTML is a build product either way.
//
// Set ARCHIFY_HOME to point at a checkout somewhere else.
// Set DIAGRAMS_STRICT=1 to make a missing archify a hard failure instead of a
// warning (worth doing in CI, if this ever gets one).

import { readdir, readFile, mkdir, access } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { dirname, resolve, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'

const run = promisify(execFile)
const here = dirname(fileURLToPath(import.meta.url))
const srcDir = resolve(here, '../diagrams')
const outDir = resolve(here, '../public/diagrams')

/** The first location that actually holds an archify CLI, or undefined. */
function findArchify() {
  const candidates = [
    process.env.ARCHIFY_HOME,
    join(homedir(), '.claude', 'skills', 'archify'),
    join(homedir(), '.agents', 'skills', 'archify'),
  ].filter(Boolean)
  for (const dir of candidates) {
    if (existsSync(join(dir, 'bin', 'archify.mjs'))) return dir
  }
  return undefined
}

async function main() {
  await mkdir(outDir, { recursive: true })

  const sources = (await readdir(srcDir)).filter((f) => f.endsWith('.json')).sort()
  if (sources.length === 0) {
    console.log('build-diagrams: no diagram sources — nothing to do')
    return
  }

  const archify = findArchify()

  if (!archify) {
    // Verify rather than regenerate. A diagram whose source exists but whose
    // artifact does not is a real problem — the page embedding it would render
    // an empty frame — so say exactly which one, and fail if asked to be strict.
    const missing = []
    for (const file of sources) {
      const name = file.replace(/\.json$/, '')
      try {
        await access(join(outDir, `${name}.html`))
      } catch {
        missing.push(name)
      }
    }
    const where = 'ARCHIFY_HOME, ~/.claude/skills/archify, ~/.agents/skills/archify'
    if (missing.length > 0) {
      const msg =
        `build-diagrams: archify not found (looked in ${where}) and ` +
        `${missing.length} artifact(s) are missing: ${missing.join(', ')}.\n` +
        `  Install it with:  npx skills add tt-a1i/archify -g`
      throw new Error(msg)
    }
    console.log(
      `build-diagrams: archify not installed — keeping the ${sources.length} committed artifact(s).\n` +
        `  (looked in ${where}; install with \`npx skills add tt-a1i/archify -g\` to regenerate)`,
    )
    if (process.env.DIAGRAMS_STRICT) throw new Error('DIAGRAMS_STRICT is set and archify is absent')
    return
  }

  for (const file of sources) {
    const name = file.replace(/\.json$/, '')
    const srcPath = join(srcDir, file)
    // The IR names its own renderer, so the type is never restated here — a
    // mismatch between filename and diagram_type cannot happen.
    const { diagram_type: type } = JSON.parse(await readFile(srcPath, 'utf8'))
    if (!type) throw new Error(`${file}: no diagram_type`)

    // `deliver` is archify's acceptance command: it freezes the spec, renders,
    // runs the artifact checks, and only then commits the HTML. A non-zero exit
    // leaves the previous artifact untouched, so a broken edit cannot silently
    // ship a blank frame.
    await run(
      'node',
      [
        join(archify, 'bin', 'archify.mjs'),
        'deliver',
        type,
        srcPath,
        join(outDir, `${name}.html`),
        '--quality',
        'showcase',
        '--json',
      ],
      { cwd: archify, maxBuffer: 64 * 1024 * 1024 },
    )
    console.log(`  ✓ ${name} (${type})`)
  }
  console.log(`build-diagrams: delivered ${sources.length} diagram(s) → public/diagrams/`)
}

main().catch((err) => {
  console.error(err.stderr || err.message || err)
  process.exit(1)
})
