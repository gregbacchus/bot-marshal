# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## [v0.4.0](https://github.com/gregbacchus/bot-marshal/compare/68f5aa7a9c920aca7e04df73fa244a7950ceb66f..v0.4.0) - 2026-09-06
#### Features
- (**audit**) add redacted request/response headers to every audit record - ([e97febd](https://github.com/gregbacchus/bot-marshal/commit/e97febdaca93b9ebd284d68863656a55c714acfb)) - test, Claude Sonnet 5
- ![BREAKING](https://img.shields.io/badge/BREAKING-red) (**config**) profile.transforms is a list, composing multiple bundles - ([74433ee](https://github.com/gregbacchus/bot-marshal/commit/74433ee2c34ade8ac5ae63e5d23d01c0dad0b976)) - test, Claude Sonnet 5
- (**secrets**) defer bootstrap's report until the tool exits, persist discovery - ([fb27207](https://github.com/gregbacchus/bot-marshal/commit/fb27207dc4a455c2a38154d78fe43b72980d6b15)) - test, Claude Sonnet 5
- (**secrets**) add --audit-log to oauth login - ([2d73d8a](https://github.com/gregbacchus/bot-marshal/commit/2d73d8a5648468f84cf6e7eb42b4fa1093e9ecbd)) - test, Claude Sonnet 5
- (**secrets**) make bootstrap capture debuggable when nothing gets captured - ([7cbaa0b](https://github.com/gregbacchus/bot-marshal/commit/7cbaa0bc096ef1e5d7ae6be9a1fda107c4f0323c)) - test, Claude Sonnet 5
- (**secrets**) add --bind/--bind-group to oauth login --run - ([21c450d](https://github.com/gregbacchus/bot-marshal/commit/21c450d7721d7c7bb3c47669b15620737701ba8d)) - test, Claude Sonnet 5
- add support for reading ID token claims from OAuth2 swaps - ([b787cde](https://github.com/gregbacchus/bot-marshal/commit/b787cde2a11c886fe6c4222f6867a18badaa0428)) - test
#### Bug Fixes
- (**ci**) stop re-dispatching a release for an already-released tag - ([dec7404](https://github.com/gregbacchus/bot-marshal/commit/dec740492a717408ff167627e6ff5bb3e0802bf7)) - test, Claude Sonnet 5
- (**http**) prefer IPv4 and retry once in the upstream guard's connect - ([9366186](https://github.com/gregbacchus/bot-marshal/commit/936618683aaf6fd7b3c3498b55ab4baf372b851d)) - test, Claude Sonnet 5
- (**secrets**) authorization_endpoint/redirect_uri aren't needed once enrolled - ([cad973b](https://github.com/gregbacchus/bot-marshal/commit/cad973b017ca55c23c040a754c2e15a4a8c4a713)) - test, Claude Sonnet 5
- (**secrets**) bootstrap's deferred report can hang forever under --mode steal - ([1406435](https://github.com/gregbacchus/bot-marshal/commit/1406435b1afad42949cce900b9677182ec2f2e2b)) - test, Claude Sonnet 5
- (**secrets**) bootstrap capture handles a JSON token request body - ([463a22f](https://github.com/gregbacchus/bot-marshal/commit/463a22f7102db2704d883a605fb7eab5c114c2c1)) - test, Claude Sonnet 5
- (**secrets**) decode Content-Encoding before parsing a bootstrap capture response - ([4b6a4de](https://github.com/gregbacchus/bot-marshal/commit/4b6a4de93cb60630ebe8411bb1aafccb907ddeb8)) - test, Claude Sonnet 5
#### Documentation
- (**cli**) don't recommend --log-sink stdout for oauth login --run - ([1659a9c](https://github.com/gregbacchus/bot-marshal/commit/1659a9c95db0d509a7601135d2acdd08d9790587)) - test, Claude Sonnet 5
- (**oauth2**) explain why in-band capture doesn't harvest client_id - ([2ee9ff2](https://github.com/gregbacchus/bot-marshal/commit/2ee9ff2e25cf64dc9a96a407eeec2951e7418d6f)) - test, Claude Sonnet 5
- (**site**) add bind groups to the Configuration sidebar - ([8538e5f](https://github.com/gregbacchus/bot-marshal/commit/8538e5fdc816d6fc2cf2fb3791c31c4fc682694c)) - test, Claude Sonnet 5
- explain why --isolation netns breaks a loopback OAuth callback - ([6d91da3](https://github.com/gregbacchus/bot-marshal/commit/6d91da3d77b04dd8c7e28dd0ce79dc30124689ca)) - test, Claude Sonnet 5
- give bootstrap capture its own section, explain in_band's client_id - ([2abb694](https://github.com/gregbacchus/bot-marshal/commit/2abb69439bee7dbd97d17e4ed2752bba09efab9d)) - test, Claude Sonnet 5
- add a decision table for the four OAuth2 credential paths - ([c734b4f](https://github.com/gregbacchus/bot-marshal/commit/c734b4f8a2ea14a95949e0ae0ad9cdc3125e9c08)) - test, Claude Sonnet 5
- split OAuth2 credentials out of Transforms into its own page - ([fddbd9c](https://github.com/gregbacchus/bot-marshal/commit/fddbd9cf8c7d7b66790e133be545b8952b311a4d)) - test, Claude Sonnet 5
- fix broken relative link to bundles.md in ADR-0036 - ([68f5aa7](https://github.com/gregbacchus/bot-marshal/commit/68f5aa7a9c920aca7e04df73fa244a7950ceb66f)) - test, Claude Sonnet 5

- - -

## [v0.3.0](https://github.com/gregbacchus/bot-marshal/compare/c5a6e5a7a126ed64b2f59977d771a6aaa032865f..v0.3.0) - 2026-09-05
#### Features
- (**identity**) identify marshal run agents without --profile - ([8f24b3b](https://github.com/gregbacchus/bot-marshal/commit/8f24b3bb4f589e34bd2d8fe536764f1056b8a5c4)) - test, Claude Sonnet 5
- rename 'launched' to 'run' in identity resolvers and related documentation - ([6b8562a](https://github.com/gregbacchus/bot-marshal/commit/6b8562a128271b86b4eeadbe62d711c7684343f7)) - test
#### Bug Fixes
- remove redundant warn-mode summary at serve startup - ([c5a6e5a](https://github.com/gregbacchus/bot-marshal/commit/c5a6e5a7a126ed64b2f59977d771a6aaa032865f)) - test, Claude Sonnet 5

- - -

## [v0.2.0](https://github.com/gregbacchus/bot-marshal/compare/f100e985a57189756f2b14548b0715af0d7ea7ff..v0.2.0) - 2026-09-04
#### Features
- allow marshal run to launch under the default profile - ([f100e98](https://github.com/gregbacchus/bot-marshal/commit/f100e985a57189756f2b14548b0715af0d7ea7ff)) - test, Claude Sonnet 5
#### Documentation
- clarify marshal run depends on a running marshal serve - ([8932301](https://github.com/gregbacchus/bot-marshal/commit/89323016f59743f393230c2e6ac150487a268d61)) - test, Claude Sonnet 5

- - -

## [v0.1.2](https://github.com/gregbacchus/bot-marshal/compare/e0be6421e4250c1e9600c251e945a067c3069a15..v0.1.2) - 2026-09-04
#### Bug Fixes
- push the prefixed tag, not the bare version, in cog's post-bump hook - ([e0be642](https://github.com/gregbacchus/bot-marshal/commit/e0be6421e4250c1e9600c251e945a067c3069a15)) - test, Claude Sonnet 5

- - -

## [v0.1.1](https://github.com/gregbacchus/bot-marshal/compare/6443d1ef2c5ecb0ee9ffdd91d71103e75a8a9619..v0.1.1) - 2026-09-04
#### Bug Fixes
- ![BREAKING](https://img.shields.io/badge/BREAKING-red) replace release-plz with cocogitto for version automation - ([3089110](https://github.com/gregbacchus/bot-marshal/commit/3089110d47dcd84b649cc33ce1628681ace570e6)) - test, Claude Sonnet 5
- skip cargo package for unpublished workspace crates in release-plz - ([d5de0de](https://github.com/gregbacchus/bot-marshal/commit/d5de0de9ab19babd2d7d5890daf5e07d0fd02878)) - Greg Bacchus, Claude Sonnet 5
- keep marshal-cli distable after publish = false - ([0f37468](https://github.com/gregbacchus/bot-marshal/commit/0f3746878b07bb961f37f22e51e1ac286f6b9275)) - Greg Bacchus, Claude Sonnet 5
- mark every crate as not published - ([ddb5e38](https://github.com/gregbacchus/bot-marshal/commit/ddb5e3804f4f7f5219884fc1fb2f9349f2edc1b4)) - Greg Bacchus, Claude Opus 5
#### Continuous Integration
- build only x86_64-linux on pull requests, every target on release - ([d0f9ccd](https://github.com/gregbacchus/bot-marshal/commit/d0f9ccdb08378aa53027fd3914b94cd4383850f1)) - test, Claude Sonnet 5
- allow the plan job's workflow hand-edit through dist's drift check - ([d52d6c0](https://github.com/gregbacchus/bot-marshal/commit/d52d6c0060c375cb431538eb76a0122424db9185)) - Greg Bacchus, Claude Sonnet 5
- skip the release build on release pull requests - ([e76faf6](https://github.com/gregbacchus/bot-marshal/commit/e76faf6413a4935c92db86f89382a7b2e3ad945a)) - Greg Bacchus, Claude Opus 5

- - -

## [0.1.0](https://github.com/gregbacchus/bot-marshal/releases/tag/v0.1.0) - 2026-09-04

### Added

- add release workflow and update documentation for Homebrew installation
- introduce env_file support for loading environment variables from a file

### Other

- Take the bootstrap command after `--`, as the rest of the CLI does
- Add bootstrap capture: learn a credential from a login you don't own
- Fix seven defects found reviewing the OAuth2 work
- Add RFC 7523: jwt_bearer grant and private_key_jwt client auth
- Add in-band OAuth2 capture: the agent drives the flow, holds nothing
- Add `marshal secrets oauth login` for the interactive grants
- Add OAuth2 as a secret source
- Add query-string and AWS SigV4 secret injection kinds
- Add an arbitrary-header injection kind for API-key style secrets
- Collapse secret injection to unconditional-only, drop the placeholder model
- Add blind credential injection, for a client that presents nothing
- Fix finding 4: netns isolation no longer binds the whole host filesystem
- Add set_headers request transform and response body size limiting
- Remove transparent capture; restore listener_port via multi-port explicit listeners
- Security review fixes: management auth, audit log mode, transparent ingress label
- Rename session to identity throughout
- Embed the default profile; remove extends; add named transform bundles
- Add gid, username, and groupname to the peer_cred resolver
- Change --log-channels (a set) to --log-detail (a level)
- Default --log-channels to log,access, not log,access,audit
- Rework logging around three named channels: log, access, audit
- Simplify logging to one sink + TTY-aware format, drop --audit-sink
- Let --audit-sink-file - mean stdout, for full JSON on the console
- Rename --audit-log to --audit-sink-file
- Rename --log-sink to --trace-sink; add --audit-sink
- Add --log-sink to force a specific log destination
- Defer to OS-level log management instead of a bespoke sink
- Default --config to the XDG user config path
- secret injection was scoped to the fallback profile, not per-profile
- Make interception mandatory; close the SOCKS5 laundering gap
- warn mode, atomic reload, management API and metrics
- transparent and DNS interception
- MCP tool-level policy
- netns isolation: enforce rather than identify
- session identity, per-session profiles, and `marshal run`
- boundary secret injection, egress DLP, and CEL rules
- TLS interception with streaming preserved
- certificate authority and per-SNI leaf minting
- explicit proxy — CONNECT, SOCKS5, upstream guard, audit trail
- workspace scaffold, core traits, config load and validation

- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).
