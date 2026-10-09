# bot-marshal launch kit

Drafts for the maintainer to review and publish. The walkthrough should be deployed before
sharing its URL. No posts have been submitted.

## Show HN

Title: Show HN: bot-marshal – a default-deny egress firewall for AI agents

Submission URL: https://bot-marshal.sh/guides/read-only-github/

Suggested opening comment:

I built bot-marshal to control the HTTP requests an AI agent can make, rather than giving it
unrestricted access to a host and hoping it uses that access appropriately.

It's a Rust MITM proxy with default-deny policy, boundary credential injection, and an audit
trail. The walkthrough lets you try it without an agent or GitHub token: permit a public
GitHub API read, refuse POST, and inspect which policy layer made each decision.

A few boundaries matter: this demo uses HTTP method policy for GitHub REST, not a universal
read-only permission model. Proxy settings alone are cooperative; Linux network namespace
isolation is the enforcement option. Clients must trust the proxy CA. The walkthrough uses
curl so those requirements are visible before configuring an agent.

I'd particularly appreciate feedback on first-run setup and which agent integrations would
make this useful in your workflow. Which services do you need your agent to read but not modify?

## Short community post

How do you let a coding agent read GitHub without also permitting write requests?

I maintain bot-marshal, an open-source egress firewall for AI agents. I've put together a
curl walkthrough showing an allowed GitHub REST read, a refused POST, and the audit trail.
No token required. It also explains the boundary between proxy routing and enforced containment.

Try it: https://bot-marshal.sh/guides/read-only-github/
Source: https://github.com/gregbacchus/bot-marshal

I'd welcome feedback on the setup, especially from people already running coding agents.

## A 60–90 second demo recording

Record two terminals side by side, with a readable font. Use only the public, token-free
walkthrough. Prepare the config and CA before recording.

1. Show the allowlist's `on_match: pass`, GET/HEAD rule, and `default_action: deny`.
2. Start the proxy with audit logging.
3. Run the repository GET: show HTTP 200 and the `rules` allow log.
4. Run POST against the same metadata endpoint: show the structured 403 and default denial.
5. Run the other-host request: show the CONNECT refusal and allowlist log.
6. Close with the walkthrough URL and note: “Proxy routing is cooperative; Linux netns
   isolation can enforce the route.”

Do not show private credentials, unrelated terminal history, or private CA keys. Describe
this as a reproducible policy demo, not a prompt-injection prevention guarantee.

## First month

| Week | Work | Evidence to collect |
|---|---|---|
| 1 | Deploy the walkthrough; verify links; submit the sitemap in Search Console; record the demo | Public walkthrough works; sitemap accepted |
| 2 | Share one launch post and one relevant community post; answer questions | Referring sites; visits to the guide; concrete setup feedback |
| 3 | Fix onboarding problems; write the credential-injection guide from a verified example | Successful trial reports; recurring questions |
| 4 | Publish an MCP restriction guide; share what was learned | Search queries and clicks; interest in specific integrations |

Initial milestone: five developers report a successful trial. This is a working target, not
a forecast. Ask which client and platform they used, whether the allowed/denied checks worked,
and where setup became unclear. Do not ask them to send secrets or full unsanitized logs.

Use Cloudflare Web Analytics for referrals and page visits, and Search Console for search
impressions, queries, and clicks. Cloudflare does not measure custom CTA or code-copy events;
do not interpret guide visits as installs or successful trials. Record voluntary trial reports
separately. Respect community posting rules and disclose maintainer involvement.
