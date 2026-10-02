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
          // Absolute URLs preserve section anchors through Starlight's path formatter.
          label: 'Explore features',
          items: [
            { label: 'Request rules', link: 'https://gregbacchus.github.io/bot-marshal/configuration/policy-layers/#rules' },
            { label: 'Secret injection', link: 'https://gregbacchus.github.io/bot-marshal/configuration/transforms/#secret-injection' },
            { slug: 'configuration/oauth2', label: 'OAuth login and renewal' },
            { slug: 'configuration/llm-routing', label: 'Model and provider routing' },
            { label: 'MCP tool controls', link: 'https://gregbacchus.github.io/bot-marshal/configuration/policy-layers/#mcp' },
            { label: 'Credential leak detection', link: 'https://gregbacchus.github.io/bot-marshal/configuration/policy-layers/#dlp' },
            { label: 'Agent identity and isolation', link: 'https://gregbacchus.github.io/bot-marshal/configuration/identity/' },
            { label: 'AI request judge', link: 'https://gregbacchus.github.io/bot-marshal/configuration/policy-layers/#judge' },
            { label: 'Header rewriting', link: 'https://gregbacchus.github.io/bot-marshal/configuration/transforms/#header-transforms' },
            { label: 'Response size limits', link: 'https://gregbacchus.github.io/bot-marshal/configuration/transforms/#response-size-limits' },
            { label: 'Management API and reload', link: 'https://gregbacchus.github.io/bot-marshal/operations/' },
            { label: 'Audit trail', link: 'https://gregbacchus.github.io/bot-marshal/observability/#the-audit-log' },
          ],
        },
        {
          label: 'Configuration',
          items: [
            { slug: 'configuration' },
            { slug: 'configuration/profiles' },
            { slug: 'configuration/policy-layers' },
            { slug: 'configuration/bundles' },
            { slug: 'configuration/bind-groups' },
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
            { slug: 'troubleshooting' },
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
