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

## Hot reload

```bash
curl -X POST -H "Authorization: Bearer $MARSHAL_MANAGEMENT_KEY" \
  http://127.0.0.1:9092/v1/reload
```

Reload builds the entire new configuration — every chain, transform and resolver — before
swapping a single pointer. **A reload that fails changes nothing**, and says so:

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
startup and refuses to start on an error, so a config that passes `check` is a config that
will start.
