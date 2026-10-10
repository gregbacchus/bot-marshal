import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { cachedDocsLoader } from '../scripts/cached-docs-loader.mjs';

export const collections = {
  docs: defineCollection({ loader: cachedDocsLoader(docsLoader()), schema: docsSchema() }),
};
