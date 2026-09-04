// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://gregbacchus.github.io',
  base: '/bot-marshal',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'bot-marshal',
      description:
        'An egress firewall for AI agents: default-deny per-request policy, credentials injected at the boundary, and a complete audit trail.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/gregbacchus/bot-marshal' },
      ],
      customCss: ['./src/styles/theme.css'],
      components: { Head: './src/components/Head.astro' },
      editLink: { baseUrl: 'https://github.com/gregbacchus/bot-marshal/edit/main/' },
      lastUpdated: true,
      expressiveCode: { themes: ['github-dark-default', 'github-light'] },
      sidebar: [
        {
          label: 'Start here',
          items: [
            { slug: 'overview', label: 'Documentation index' },
            { slug: 'getting-started' },
            { slug: 'concepts' },
          ],
        },
        {
          label: 'Configuration',
          items: [
            { slug: 'configuration' },
            { slug: 'configuration/profiles' },
            { slug: 'configuration/policy-layers' },
            { slug: 'configuration/bundles' },
            { slug: 'configuration/transforms' },
            { slug: 'configuration/identity' },
            { slug: 'configuration/secret-injection-examples' },
          ],
        },
        {
          label: 'Running it',
          items: [
            { slug: 'cli' },
            { slug: 'capture' },
            { slug: 'observability' },
            { slug: 'operations' },
            { slug: 'production' },
          ],
        },
        {
          label: 'Design',
          items: [
            { slug: 'roadmap' },
            { label: 'Architecture decisions', autogenerate: { directory: 'adr' } },
          ],
        },
      ],
    }),
  ],
});
