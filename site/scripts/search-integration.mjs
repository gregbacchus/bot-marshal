import * as pagefind from 'pagefind';
import { fileURLToPath } from 'node:url';

// Keep Starlight's search UI and replace only its shell-based indexing hook.
// The Pagefind API also lets an indexing failure fail the build.
export function shellFreeSearch(integration, service = pagefind) {
  return {
    ...integration,
    hooks: {
      ...integration.hooks,
      async 'astro:build:done'({ dir, logger }) {
        const check = (result) => {
          if (result.errors?.length) throw new Error(result.errors.join('\n'));
          return result;
        };
        try {
          const { index } = check(await service.createIndex());
          if (!index) throw new Error('Pagefind did not create an index');
          const { page_count } = check(await index.addDirectory({ path: fileURLToPath(dir) }));
          check(await index.writeFiles({ outputPath: fileURLToPath(new URL('pagefind/', dir)) }));
          logger.info(`Pagefind indexed ${page_count} pages`);
        } finally {
          await service.close();
        }
      },
    },
  };
}
