#!/usr/bin/env node
// Mirrors ../docs into src/content/docs, because Starlight needs frontmatter and
// URL-shaped links while docs/ has to stay plain, GitHub-readable markdown.
// The mirror is generated: never edit src/content/docs by hand.

import { promises as fs } from 'node:fs';
import fssync from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const SITE = path.resolve(here, '..');
const DOCS = path.resolve(SITE, '../docs');
const OUT = path.join(SITE, 'src/content/docs');
const BASE = '/bot-marshal';
const REPO = 'https://github.com/gregbacchus/bot-marshal/blob/main';

// A short, human subtitle per page. Starlight shows it under the title and in
// search results, so a missing one is a visible gap rather than a nicety.
const DESCRIPTIONS = {
  'overview': 'Default-deny egress control for AI agents: policy, credential injection, and a complete audit trail.',
  'getting-started': 'Build it, write a minimal config, generate a CA, and put a request through it.',
  'concepts': 'How a request travels from capture through identity, policy and transforms.',
  'cli': 'Every subcommand and global flag.',
  'capture': 'Explicit proxy and DNS interception.',
  'observability': 'Logs, the audit trail, and what to watch.',
  'operations': 'The management API, hot reload, and rolling out default-deny.',
  'production': 'Service layout, systemd, and file permissions.',
  'roadmap': 'What is built, what is next, and what was deliberately dropped.',
  'configuration/index': 'The config file, and how it splits across profiles, bundles and transforms.',
  'configuration/profiles': 'The unit of policy: embedded and named profiles.',
  'configuration/policy-layers': 'denylist, allowlist, rules, dlp, mcp and judge.',
  'configuration/bundles': 'Named, reusable allow-lists.',
  'configuration/bind-groups': 'Named, reusable sandbox bind paths for marshal run --isolation netns.',
  'configuration/transforms': 'Header filtering, secret injection, and response rewriting.',
  'configuration/oauth2': 'Grants, private-key client auth, and capturing an agent-driven OAuth flow in band.',
  'configuration/identity': 'Which agent is connecting, and marshal run.',
  'configuration/secret-injection-examples': 'Worked examples of injecting real credentials at the boundary.',
  'adr/index': 'Why the design is the way it is.',
};

// docs/README.md is the documentation index; the site root is a hand-written
// splash page instead, so it lands at /overview.
// Not published: it is a scaffold for authors, not a document to read.
const EXCLUDED = new Set(['adr/template.md']);

const slugFor = (rel) =>
  rel === 'README.md'
    ? 'overview'
    : rel.replace(/\.md$/, '').replace(/(^|\/)README$/, '$1index');

/** Turn a docs-relative markdown link into a site URL, or a GitHub link if it
 *  points outside docs/. */
function rewriteTarget(target, fromRel) {
  if (/^(https?:|mailto:|#)/.test(target)) return target;
  const [pathPart, hash = ''] = target.split('#');
  const suffix = hash ? `#${hash}` : '';
  if (!pathPart) return target;

  const resolved = path.posix.normalize(
    path.posix.join(path.posix.dirname(fromRel), pathPart),
  );
  if (resolved.startsWith('..')) {
    // Escapes docs/ — it is a repository file, so send the reader to GitHub.
    return `${REPO}/${path.posix.normalize(path.posix.join('docs', path.posix.dirname(fromRel), pathPart))}${suffix}`;
  }
  if (!/\.md$/.test(pathPart) && !pathPart.endsWith('/')) return target;
  if (EXCLUDED.has(resolved)) return `${REPO}/docs/${resolved}${suffix}`;
  const slug = slugFor(resolved).replace(/(^|\/)index$/, '');
  return `${BASE}/${slug}${slug ? '/' : ''}${suffix}`;
}

function transform(src, rel) {
  let body = src;

  // The first H1 is the page title; Starlight renders its own, so drop it.
  const m = body.match(/^\s*#\s+(.+?)\s*$/m);
  const title = m ? m[1] : path.basename(rel, '.md');
  if (m) body = body.replace(m[0], '').replace(/^\s*\n/, '');

  // Rewrite links, but not the ones inside fenced code blocks.
  const chunks = body.split(/(^```[\s\S]*?^```$)/m);
  body = chunks
    .map((c, i) =>
      i % 2
        ? c
        : c.replace(/\]\(([^)\s]+)(\s+"[^"]*")?\)/g, (_, t, ti = '') => `](${rewriteTarget(t, rel)}${ti})`),
    )
    .join('');

  const slug = slugFor(rel);
  const description = DESCRIPTIONS[slug];
  const fm = [
    '---',
    `title: ${JSON.stringify(title)}`,
    ...(description ? [`description: ${JSON.stringify(description)}`] : []),
    `editUrl: ${REPO}/docs/${rel}`,
    '---',
    '',
  ].join('\n');
  return fm + body.trimStart();
}

async function walk(dir, base = '') {
  const out = [];
  for (const e of await fs.readdir(dir, { withFileTypes: true })) {
    const rel = path.posix.join(base, e.name);
    if (e.isDirectory()) out.push(...(await walk(path.join(dir, e.name), rel)));
    else if (e.name.endsWith('.md')) out.push(rel);
  }
  return out;
}

async function sync() {
  const files = (await walk(DOCS)).filter((f) => !EXCLUDED.has(f));
  await fs.rm(OUT, { recursive: true, force: true });
  await fs.mkdir(OUT, { recursive: true });
  // The splash page is authored here, not in docs/, but lives in the same
  // collection — so it is copied in after the wipe.
  await fs.cp(path.join(SITE, 'src/home'), OUT, { recursive: true });
  for (const rel of files) {
    const dest = path.join(OUT, `${slugFor(rel)}.md`);
    await fs.mkdir(path.dirname(dest), { recursive: true });
    await fs.writeFile(dest, transform(await fs.readFile(path.join(DOCS, rel), 'utf8'), rel));
  }
  console.log(`[sync-docs] ${files.length} pages -> src/content/docs`);
}

await sync();

if (process.argv.includes('--watch')) {
  let queued = null;
  fssync.watch(DOCS, { recursive: true }, () => {
    clearTimeout(queued);
    queued = setTimeout(() => sync().catch(console.error), 100);
  });
  console.log('[sync-docs] watching ../docs');
  setInterval(() => {}, 1 << 30);
}
