import { readFile } from 'node:fs/promises';

// Astro 5 treats changed cached entries as duplicate IDs. Evict only changed files;
// retaining unchanged entries preserves caching and detection of genuine slug collisions.
export function cachedDocsLoader(loader) {
  return {
    ...loader,
    async load(context) {
      for (const [id, entry] of context.store.entries()) {
        if (!entry.filePath) continue;
        try {
          const content = await readFile(new URL(entry.filePath, context.config.root), 'utf8');
          if (context.generateDigest(content) !== entry.digest) context.store.delete(id);
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
          context.store.delete(id);
        }
      }
      return loader.load(context);
    },
  };
}
