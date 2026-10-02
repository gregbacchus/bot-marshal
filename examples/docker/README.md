# Two containers through an explicit proxy

This example routes cooperative clients through marshal using `HTTP_PROXY` and `HTTPS_PROXY`.
Static source addresses select separate named profiles: `agent-a` may reach GitHub;
`agent-b` may reach the Anthropic API. Both trust the proxy CA. The clients receive only the
certificate, while the proxy mounts its private key separately in its read-only CA directory.

## Start from the repository root

Docker with the Compose plugin is required. The image builds marshal from source, so its
build needs access to Rust dependencies. Generate the CA **inside the image**, where the
configured `/etc/marshal/ca` paths exist:

```bash
cd examples/docker
mkdir -p ca
docker compose build proxy
docker compose run --rm --no-deps \
  -v "$PWD/ca:/etc/marshal/ca" proxy ca init
docker compose run --rm --no-deps proxy config check
docker compose up -d
```

The temporary writable mount lets `ca init` create its files; normal proxy operation mounts
that directory read-only. `ca init` refuses to overwrite an existing CA. Both profile files
are mounted beside the base config, because marshal loads `profiles/` relative to it.

## Check policy and attribution

```bash
docker compose exec agent-a curl -sS -o /dev/null -w '%{http_code}\n' https://api.github.com/zen
docker compose exec agent-a curl -sS -o /dev/null -w '%{http_code}\n' https://api.anthropic.com/
docker compose exec agent-b curl -sS -o /dev/null -w '%{http_code}\n' https://api.anthropic.com/
docker compose logs proxy
```

Expect GitHub traffic from `agent-a` to be allowed and its Anthropic request to be denied
with `403`. The Anthropic request from `agent-b` is allowed by marshal, but the upstream can
return its own error status: this example injects no API credentials. Use the log's identity,
profile and reason fields to distinguish a proxy refusal from an upstream response.

## Containment and cleanup

Proxy variables are routing preferences, not isolation. Clients can bypass them unless the
container network or an external firewall blocks direct egress. DNS answers alone do not
provide HTTP/TLS ingress; see [Capture](../../docs/capture.md#dns). Marshal does not include a
host firewall recipe. `marshal run --isolation netns` is the Linux process-launch alternative.

```bash
docker compose down
```

Keep `ca/ca.key` private. Removing it and creating a new CA requires redistributing the new
certificate to any clients that trusted the old one.

## Podman

The Compose layout can also be used with a Podman Compose provider. User-namespace mappings,
bind-mount permissions and SELinux labels vary by host; verify that the proxy can read the CA
key and clients can read the certificate before assuming a Docker command is interchangeable.
See [Capture](../../docs/capture.md#containers-dockerpodman) for the routing assumptions.
