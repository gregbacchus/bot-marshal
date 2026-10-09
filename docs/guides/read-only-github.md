# Give an AI agent read-only GitHub API access

A host allowlist lets an agent reach GitHub, but does not distinguish reading a repository
from modifying it. This walkthrough permits `GET` and `HEAD` requests to `api.github.com`,
refuses other methods, and refuses other destinations. You can see the difference with curl
before configuring an agent. No GitHub token or private repository is needed.

This is read-only **HTTP method policy for the GitHub REST API**, not a universal read-only
GitHub permission model. Git over SSH, GraphQL queries sent using POST, and requests that
bypass the proxy are outside this example.

## Start a separate demo proxy

Install [bot-marshal](../getting-started.md#install) and curl. These commands use a separate
configuration directory and port 18080 so the demo does not replace your usual policy.
Run them in a Bash-compatible terminal on Linux or macOS.

```bash
mkdir -p "$HOME/bot-marshal-github-demo"
cat > "$HOME/bot-marshal-github-demo/config.yaml" <<'CFG'
listeners:
  explicit:
    listen: "127.0.0.1:18080"
tls:
  ca_cert: "~/bot-marshal-github-demo/ca.crt"
  ca_key: "~/bot-marshal-github-demo/ca.key"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { domains: ["api.github.com"] }
      on_match: pass
      on_miss: deny
    - layer: rules
      expressions:
        - when: 'req.host == "api.github.com" && req.method in ["GET", "HEAD"]'
          verdict: allow
CFG
marshal --config "$HOME/bot-marshal-github-demo/config.yaml" config check
marshal --config "$HOME/bot-marshal-github-demo/config.yaml" ca init
marshal --config "$HOME/bot-marshal-github-demo/config.yaml" serve \
  --log-detail audit --log-sink stdout --log-format pretty
```

Keep that terminal open. Starting `serve` also compiles the CEL rule; configuration
validation alone does not prove that expressions can run.

`on_match: pass` is essential: setting it to `allow` would approve all GitHub requests before
the method rule could inspect them. Unmatched methods reach `default_action: deny`.

## Permit a read

In a second terminal:

```bash
curl --noproxy '' --cacert "$HOME/bot-marshal-github-demo/ca.crt" \
  --proxy http://127.0.0.1:18080 \
  https://api.github.com/repos/gregbacchus/bot-marshal \
  --output /tmp/bot-marshal-github-read.json --write-out 'HTTP %{http_code}\n'
```

Expected: `HTTP 200` and repository metadata in the output file. The proxy terminal should
record `allow`, `host=api.github.com`, `method=GET`, and `layer=rules`. An upstream rate limit
or network error can change the HTTP result; check the policy verdict separately.

## Refuse a write method

Use the same public metadata endpoint with POST. This does not attempt to create or change
repository content, even if you accidentally run it without the proxy.

```bash
curl --noproxy '' --cacert "$HOME/bot-marshal-github-demo/ca.crt" \
  --proxy http://127.0.0.1:18080 \
  --request POST https://api.github.com/repos/gregbacchus/bot-marshal \
  --write-out '\nHTTP %{http_code}\n'
```

Expected: a structured refusal body and `HTTP 403`. The proxy log should record `deny`,
`method=POST`, and `layer=default_action`. The request is refused before forwarding.

To check the destination boundary too:

```bash
curl --noproxy '' --cacert "$HOME/bot-marshal-github-demo/ca.crt" \
  --proxy http://127.0.0.1:18080 https://example.com/ \
  --write-out '\nHTTP %{http_code}\n'
```

Expected: curl reports `CONNECT tunnel failed, response 403` and may print `HTTP 000`.
The destination is refused during CONNECT, before TLS interception; inspect `layer=allowlist`
in the denial log rather than expecting an ordinary HTTPS response body.

## Use this policy with an agent

Configure the client's HTTP proxy and CA trust using the [client setup guide](../getting-started.md#point-a-real-agent-at-it).
Do not assume every client honors proxy environment variables. This narrow demo also blocks
model providers, package registries, and other services an agent may need; add their policies
separately rather than broadly allowing GitHub before the method check.

Proxy routing alone is cooperative. An agent that can connect directly can bypass this policy.
For enforced Linux routing, follow the [network namespace instructions](../configuration/identity.md#netns-enforces-rather-than-identifies).
Use a GitHub credential with appropriately limited permissions as an additional boundary.

For private repository access, see [secret injection](../configuration/transforms.md#secret-injection).
The demo does not inject credentials or establish per-agent identity; its fallback profile
applies to all clients reaching this listener.

Stop the demo with Ctrl-C. If something fails, check [TLS and policy troubleshooting](../troubleshooting.md).
If you try this with an agent, [open a GitHub issue](https://github.com/gregbacchus/bot-marshal/issues)
with the client, platform, and sanitized error output. Do not include credentials or CA private keys.
