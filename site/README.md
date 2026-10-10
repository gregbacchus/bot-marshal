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

## Build checks

Run `npm test` for the content-cache and search-index failure regressions, then `npm run build`.
The docs loader evicts changed or removed cached files before loading them, working around
Astro 5's duplicate-ID warning for updated entries while retaining unchanged collision
records. It does not suppress duplicate-ID diagnostics.

Search stays enabled in Starlight. `scripts/search-integration.mjs` replaces its shell-based
build hook with the Pagefind Node API, uses the pinned direct dependency, and fails the build
if indexing or writing the search bundle fails. This avoids Node's `DEP0190` warning without
hiding deprecations or disabling search.

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

## Google Search discovery

Starlight emits static HTML, page titles, descriptions, canonical URLs, and an XML sitemap.
`public/robots.txt` allows crawling and advertises `https://bot-marshal.sh/sitemap-index.xml`.
The homepage includes WebSite structured data identifying the site name. Page descriptions
are maintained in `scripts/sync-docs.mjs`; the homepage metadata lives in `src/home/index.mdx`.

After deploying to the custom domain:

1. Add a **Domain property** for `bot-marshal.sh` in [Google Search Console](https://search.google.com/search-console).
2. Add Google's supplied TXT verification record in Cloudflare DNS, then verify ownership.
3. Submit `https://bot-marshal.sh/sitemap-index.xml` in **Sitemaps**.
4. Use **URL inspection** on the homepage and getting-started page, test the live URLs,
   and request indexing. Monitor **Page indexing** and **Performance** for crawl errors,
   impressions, search queries, and clicks.

Confirm the public sitemap and robots file return HTTP 200, and that Cloudflare does not
challenge Googlebot. Search Console measures Google discovery; Cloudflare Web Analytics
measures visits after readers arrive. Sitemap submission does not guarantee indexing or ranking.
