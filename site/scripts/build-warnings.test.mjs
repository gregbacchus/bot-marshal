import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { cachedDocsLoader } from './cached-docs-loader.mjs';
import { shellFreeSearch } from './search-integration.mjs';

test('changed and removed cached files are evicted; unchanged collision evidence remains', async () => {
  const root = await mkdtemp(join(tmpdir(), 'marshal-loader-'));
  try {
    await writeFile(join(root, 'changed.md'), 'new');
    await writeFile(join(root, 'unchanged.md'), 'same');
    const store = new Map([
      ['changed', { filePath: 'changed.md', digest: 'old' }],
      ['unchanged', { filePath: 'unchanged.md', digest: 'same' }],
      ['removed', { filePath: 'removed.md', digest: 'old' }],
    ]);
    let called = false;
    const loader = cachedDocsLoader({ name: 'docs', load(context) {
      called = true;
      assert.deepEqual([...context.store.keys()], ['unchanged']);
    } });
    await loader.load({ store, config: { root: pathToFileURL(root + '/') }, generateDigest: (content) => content });
    assert.ok(called);
  } finally { await rm(root, { recursive: true }); }
});

test('search indexing preserves other hooks and fails the build on Pagefind errors', async () => {
  const configHook = () => {};
  let closed = false;
  const service = {
    createIndex: async () => ({ index: { addDirectory: async () => ({ errors: ['indexing failed'] }) } }),
    close: async () => { closed = true; },
  };
  const integration = shellFreeSearch({ name: 'starlight', hooks: { 'astro:config:setup': configHook } }, service);
  assert.equal(integration.hooks['astro:config:setup'], configHook);
  await assert.rejects(integration.hooks['astro:build:done']({ dir: new URL('file:///tmp/site/'), logger: { info() {} } }), /indexing failed/);
  assert.ok(closed);
});
