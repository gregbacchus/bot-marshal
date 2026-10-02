# Operations

## The management API

```yaml
listeners:
  management:
    listen: "127.0.0.1:9092"
    api_key_env: "MARSHAL_MANAGEMENT_KEY"
```

| endpoint | auth | purpose |
|---|---|---|
| `GET /v1/healthz` | none | alive, generation, profiles, warn-mode profiles |
| `GET /v1/metrics` | none | Prometheus counters by profile and identity |
| `GET /v1/identities` | bearer | what each agent has done |
| `POST /v1/reload` | bearer | re-read config and swap atomically |

Bearer auth reads the key from the environment variable named by `api_key_env` — or from the
[env file](configuration/README.md#the-env-file), if the environment does not have it. Bind it to
loopback unless something specifically needs otherwise.

### Responses and authentication

`GET /v1/healthz` returns JSON with `status`, `version`, `generation`, `profiles`,
`passthrough_configured` and `warn_only_profiles`. `profiles` lists named profiles; the
embedded fallback has no name. Health means the process is alive, not that every upstream is
reachable or every optional listener bound successfully.

`GET /v1/identities` returns `{"identities": [...]}`. Each row contains `identity`, `allowed`,
`denied` and `would_deny`. Counters live in memory and reset on restart. The metrics endpoint
returns Prometheus text; see [Observability](observability.md#metrics).

Authenticated endpoints return HTTP `401` with `{"error":"unauthorized"}` for a missing or
incorrect bearer token. If the configured key variable is unset, those endpoints refuse every
request; health and metrics remain available. The key is selected at startup, so rotating it
or changing `api_key_env` requires a restart.

Successful reload returns HTTP `200` with `status: "reloaded"`, `generation`, `profiles` and
`warn_only_profiles`. Rejected reload returns HTTP `400` with `status: "rejected"`, `error`
and `note`, keeping the old runtime. Check the HTTP status as well as the JSON result.

## Hot reload

```bash
curl -X POST -H "Authorization: Bearer $MARSHAL_MANAGEMENT_KEY" \
  http://127.0.0.1:9092/v1/reload
```

Reload loads the configuration and builds new policy chains, transforms, identity resolvers
and TLS runtime before swapping a single pointer. Listener sockets and the forwarding
upstream guard are created at startup and are not replaced by that swap. **A reload that fails changes nothing**, and says so:

```json
{ "status": "rejected",
  "error": "profiles.coding-agent.policy[0]: references unknown bundle `does-not-exist`",
  "note": "the previously loaded configuration is still in effect" }
```

A connection reads the runtime once and keeps that view, so a reload never changes the rules
under a request already in flight.

**The [env file](configuration/README.md#the-env-file) is not re-read.** Reload rebuilds the
configuration, but the variables the env file supplied were read once at startup, so a changed
`.env` needs a restart. A credential that rotates on its own belongs in a `file` source (which
has a TTL) or an `oauth2` one, not in the env file.

### What reload changes

| setting | how to apply a change |
|---|---|
| profiles, policy, bundles, transforms, identity resolvers | reload; new connections use the new runtime |
| TLS CA, leaf cache settings, passthrough, upstream trust roots | rebuilt on reload for new connections |
| `upstream.max_response_bytes` | reload; the default response limiter is rebuilt |
| `upstream.deny_cidrs`, `upstream.allow_private` | restart to replace the forwarding guard; newly built OAuth sources can see the new values on reload, so restart avoids mixed guard configurations |
| explicit, Unix, DNS and management listeners; DNS records/passthrough | restart; existing servers are not rebound/reconfigured |
| management API key, env-file values, `state_dir` | restart |
| log settings and audit-file destination | restart with the new CLI flags |

Existing connections keep their old runtime until they close. Reload does not force open TLS
tunnels onto a tightened policy; restart if the change must affect established traffic now.
OAuth token/grant caches survive reload. If you need fresh credentials, see
[OAuth2 cache behavior](configuration/oauth2.md#what-this-costs).

## Rolling it out

Turning default-deny on for an existing agent breaks everything it was quietly relying on, and
that list cannot be known in advance. Warn mode is how it gets discovered:

```yaml
# profiles/coding-agent.yaml
mode: warn      # run the whole chain, record refusals, forward anyway
```

Audit records then carry `would_deny: true` while `action` stays `allow`. Filter on it to
build the allowlist from real traffic, then set `mode: enforce`.

```bash
jq -c 'select(.would_deny) | .host' /var/log/bot-marshal/audit.jsonl | sort | uniq -c | sort -rn
```

It is deliberately noisy — a startup warning, a `config check` warning, a log line per
request, a `marshal_would_deny_total` counter, and a `warn_only_profiles` field in
`/v1/healthz` — because **a proxy silently in warn mode is worse than no proxy**: somebody
believes it is protecting them.

## A rollout that works

1. Write the profile with `mode: warn` and a `default_action: deny` chain you believe is right.
2. Run the agent's real workload through it for long enough to cover its periodic work — a
   nightly job's dependency fetch is exactly the thing an hour of observation misses.
3. Read `would_deny` off the audit log, decide which hosts are legitimate, and add them to a
   [bundle](configuration/bundles.md) rather than the profile, so the next profile benefits.
4. Flip to `mode: enforce`. Watch `/v1/healthz` no longer list the profile under
   `warn_only_profiles`.

## Checking before restart

```bash
marshal --config /etc/bot-marshal/marshal.yaml config check
```

Exits non-zero on any error and prints every diagnostic. `serve` applies the same rules at
startup and refuses invalid configuration. Passing `check` validates configuration structure
and secret-source construction; it does not prove that `serve` can start. CA files, judge
credentials, filesystem permissions and available listener ports must also be checked by
starting the service. Credential sources are not fetched during validation, and upstream
availability is only established when traffic uses it.
