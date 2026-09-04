# Documentation site

The published site at <https://gregbacchus.github.io/bot-marshal/> is
[Astro Starlight](https://starlight.astro.build/) over the markdown in [`../docs`](../docs).

`docs/` stays the source of truth and stays readable on GitHub.
`scripts/sync-docs.mjs` mirrors it into `src/content/docs/` (gitignored, regenerated on every
build), adding the frontmatter Starlight needs and rewriting relative `*.md` links to site
URLs — links that point outside `docs/` become GitHub links instead.

## Preview locally

```bash
cd site
npm install
npm run dev
```

<http://localhost:4321/bot-marshal/>. Edits to `../docs` re-sync and hot-reload.

```bash
npm run build && npm run preview   # exactly what CI publishes
```

## Adding a page

Add the markdown under `docs/`, then add it to the `sidebar` in `astro.config.mjs` — ADRs are
picked up automatically. A page's title comes from its first `#` heading; give it a subtitle by
adding an entry to `DESCRIPTIONS` in `scripts/sync-docs.mjs`.

`.github/workflows/docs.yml` deploys on push to `main`. GitHub Pages must be set to
**Source: GitHub Actions** in the repository settings.
