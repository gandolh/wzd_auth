// @ts-check
import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'

/**
 * Ward's documentation site.
 *
 *   • Narrative  → authored here (the pages under src/content/docs/*.mdx).
 *   • Corpus     → synced by scripts/sync-corpus.mjs into src/content/docs/wiki/.
 *                  Never edit those by hand; edit corpus/ and rebuild.
 *   • Reference  → generated into public/reference/client/ by TypeDoc from
 *                  @ward/client's public barrel.
 *   • Diagrams   → compiled by scripts/build-diagrams.mjs (archify) from the
 *                  typed JSON IR in diagrams/, into public/diagrams/.
 *
 * The base path is a sub-path deploy on the estate's single origin:
 * https://gandolh.ro/ward/docs/. Left at "/" for local `astro preview`; the
 * vps-deploy build passes DOCS_BASE. See vps-deploy/docs/docs-route-convention.md.
 */
// The deployed base path, baked in rather than injected at deploy time.
//
// vps-deploy ships what this repo already built and VERIFIES this base — it does
// not set it. That is the estate's rule for the case that matters most (Ward's
// UI does the same, see vps-deploy/stacks/ward.ts): a variable the deploy passes
// that changes nothing is a variable that can silently disagree, whereas a value
// baked here and checked there cannot. Build with `npm run docs`; a wrong base
// fails the deploy by name instead of shipping a page whose every asset 404s.
//
// DOCS_BASE still overrides it, for building a copy to serve from somewhere else.
const base = process.env.DOCS_BASE ?? '/ward/docs/'

export default defineConfig({
  base,
  // The estate's one canonical origin. Set so the sitemap Starlight generates
  // carries absolute URLs; `base` above supplies the path half.
  site: 'https://gandolh.ro',
  integrations: [
    starlight({
      title: 'Ward',
      description:
        'One sign-in for every side project on the shared VPS — architecture, sessions and tokens, grants, the HTTP surface, and the contract every consuming app implements.',
      tagline: 'One identity, one credential store, one set of access grants.',
      customCss: ['./src/styles/theme.css'],
      // Light only. Ward's own UI is a light "limestone" surface with a single
      // accent, and the docs take the same ground — see src/styles/theme.css for
      // why the console's dark palette is quoted rather than adopted.
      components: {
        ThemeProvider: './src/components/ThemeProvider.astro',
        ThemeSelect: './src/components/ThemeSelect.astro',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/gandolh/wzd_auth',
        },
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'What Ward is', link: '/' },
            { label: 'Architecture', link: '/architecture/' },
            { label: 'The one-origin estate', link: '/topology/' },
          ],
        },
        {
          label: 'How it works',
          items: [
            { label: 'Sessions and tokens', link: '/sessions/' },
            { label: 'Introspection and revocation', link: '/introspection/' },
            { label: 'Grants — the security boundary', link: '/grants/' },
            { label: 'App keys', link: '/app-keys/' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'HTTP API', link: '/api/' },
            { label: 'Data model', link: '/data/' },
            { label: 'Configuration', link: '/configuration/' },
            {
              label: '@ward/client (TypeDoc) ↗',
              link: '/reference/client/',
              attrs: { target: '_blank' },
            },
          ],
        },
        {
          label: 'Integrate an app',
          items: [{ label: 'The integration contract', link: '/wiki/integrating/' }],
        },
        {
          label: 'Deep dive — from the corpus',
          items: [
            { label: 'Overview', link: '/wiki/overview/' },
            { label: 'The estate as it stands', link: '/wiki/estate/' },
            { label: 'Glossary', link: '/wiki/glossary/' },
            { label: 'Decisions — foundations', link: '/wiki/decisions/' },
            { label: 'Decisions — accounts', link: '/wiki/decisions-accounts/' },
            { label: 'Decisions — tokens', link: '/wiki/decisions-tokens/' },
            { label: 'Decisions — admin', link: '/wiki/decisions-admin/' },
            { label: 'Decisions — app keys', link: '/wiki/decisions-app-keys/' },
            { label: 'Decisions — implementation', link: '/wiki/decisions-implementation/' },
            { label: 'Landscape — roads not taken', link: '/wiki/landscape/' },
            { label: 'Open questions', link: '/wiki/open-questions/' },
          ],
        },
        {
          label: 'Status',
          items: [
            { label: 'Status snapshot', link: '/wiki/status/' },
            { label: 'Change log', link: '/wiki/log/' },
          ],
        },
      ],
    }),
  ],
})
