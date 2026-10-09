# Documentation site

The published site at <https://bot-marshal.sh/> is
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

<http://localhost:4321/>. Edits to `../docs` re-sync and hot-reload.

```bash
npm run build && npm run preview   # exactly what CI publishes
```

## Adding a page

Add the markdown under `docs/`, then add it to the `sidebar` in `astro.config.mjs` — ADRs are
picked up automatically. A page's title comes from its first `#` heading; give it a subtitle by
adding an entry to `DESCRIPTIONS` in `scripts/sync-docs.mjs`.

`.github/workflows/docs.yml` deploys on push to `main`. GitHub Pages must be set to
**Source: GitHub Actions** in the repository settings.

## Visitor analytics

Cloudflare Web Analytics is installed manually in `src/components/Head.astro`, shared by
the homepage and every documentation page. The beacon token identifies the analytics site;
it is public, not an API credential. View traffic and performance in Cloudflare's
**Web Analytics** dashboard for `bot-marshal.sh`. Local previews use a different hostname
and do not verify production data collection.

Keep Cloudflare's automatic script injection disabled for this site to avoid installing a
second beacon. In Manage site, use **Enable with JS Snippet installation** if the domain
is proxied through Cloudflare. This integration measures page visits and performance;
Cloudflare Web Analytics does not support custom click or code-copy events.

The site is built for the root of `https://bot-marshal.sh/`. Configure that custom domain
and HTTPS in the repository's GitHub Pages settings; DNS configuration alone does not
change the Pages domain.
