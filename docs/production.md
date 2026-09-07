# Production

## Run the proxy as its own user

The proxy itself, and the agents `marshal run` launches, are two separate concerns that can run
as different users. Nothing requires them to be the same, and there is a reason to keep them
apart: **the proxy process holds the CA private key and the real credentials
`request_transforms.secrets` inject**, so it is worth minimising what else runs as that user.

```bash
sudo useradd --system --no-create-home --home-dir /var/lib/bot-marshal bot-marshal
sudo mkdir -p /etc/bot-marshal /var/lib/bot-marshal
sudo chown bot-marshal:bot-marshal /var/lib/bot-marshal
sudo chmod 0700 /var/lib/bot-marshal

# Minimum config.yaml to get `config check` and `serve` running: listeners, the CA paths and
# state_dir under /var/lib/bot-marshal, and the required embedded `profile:` (deny-all until
# you add policy — see Configuration). Add profiles/, bundles/, transforms/ next to it as your
# policy grows.
sudo tee /etc/bot-marshal/config.yaml > /dev/null <<'YAML'
listeners:
  explicit:
    listen: "127.0.0.1:8080"
    unix_socket: "/var/lib/bot-marshal/marshal.sock"   # unlocks SO_PEERCRED identity

tls:
  ca_cert: "/var/lib/bot-marshal/ca.crt"
  ca_key: "/var/lib/bot-marshal/ca.key"

state_dir: "/var/lib/bot-marshal/state"

profile:
  default_action: deny
YAML
sudo chown root:bot-marshal /etc/bot-marshal/config.yaml
sudo chmod 0640 /etc/bot-marshal/config.yaml
```

If `marshal` was installed via Homebrew, it lives under the Homebrew prefix (e.g.
`/home/linuxbrew/.linuxbrew/bin/marshal` or `/opt/homebrew/bin/marshal`), which is only on
`PATH` for shells that source Homebrew's shellenv. `bot-marshal` is a service user with no such
shell setup, so `sudo -u bot-marshal marshal ...` and, later, systemd's `ExecStart` both fail
with "command not found". Symlink the binary into `/usr/local/bin`, which is on the default
system `PATH` and needs no per-user setup, before doing anything else as that user:

```bash
sudo ln -sf "$(brew --prefix)/bin/marshal" /usr/local/bin/marshal
```

```bash
sudo -u bot-marshal marshal --config /etc/bot-marshal/config.yaml ca init
```

### `state_dir`

`/var/lib/bot-marshal` is also where `state_dir` belongs — the one directory marshal *writes*
rather than reads. Today it holds OAuth2 refresh tokens obtained by
[`marshal secrets oauth login`](cli.md#marshal-secrets-oauth-login-name---open---timeout-duration).

Marshal creates `<state_dir>/oauth/` mode `0700` and each grant file `0600`, and **refuses to
use a directory any other local user can read** rather than quietly tightening it — a refresh
token that has already been readable by someone else wants re-enrolling, not locking down after
the fact. So the directory must be owned by the proxy's user and not group- or world-readable.

Two operational consequences:

* **Back it up, or be able to re-enrol.** For `grant: authorization_code` and `grant:
  device_code` the refresh token is the only copy; losing it means a human at a browser again.
  It is a live credential, so a backup of it needs the same protection as the CA key.
* **`state_dir` changes take effect on restart, not on reload.** Moving live credentials to a
  new directory underneath a running process would be worse than making the operator say when.

`marshal secrets oauth status` reports which credentials are enrolled and how long ago, which is
the check to run after a restore.

## systemd unit

`ExecStart` below points at `/usr/local/bin/marshal` — the symlink created above — rather than
a Homebrew path, for the same PATH reason.

```ini
# /etc/systemd/system/bot-marshal.service
[Unit]
Description=bot-marshal egress proxy
After=network.target

[Service]
User=bot-marshal
Group=bot-marshal
ExecStart=/usr/local/bin/marshal --config /etc/bot-marshal/config.yaml serve
Restart=on-failure
# Only if listeners.dns or listeners.explicit binds a port below 1024.
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now bot-marshal
journalctl -u bot-marshal -f
```

Under a systemd unit, `--log-sink auto` finds journald and every field lands as a structured
journal field — see [Observability](observability.md#under-journald).

## Config layout

Pass `--config` explicitly for a service; the `$XDG_CONFIG_HOME` default is for interactive
use and is the wrong answer for a daemon.

```
/etc/bot-marshal/
├── config.yaml
├── .env            # mode 0600 — the credentials `env` sources name (optional)
├── profiles/
├── bundles/
└── transforms/
/var/lib/bot-marshal/
├── ca.crt
└── ca.key          # mode 0600 — whoever holds this can impersonate every site
```

Secret files a `file`-type source points at belong here too, readable only by the service user.

Under systemd, `EnvironmentFile=` and the [env file](configuration/README.md#the-env-file) do
the same job, and the environment wins where both set a variable. Pick one — two places to look
is how a rotated token ends up applied in the one that loses. The env file is read once at
startup, so either way a change needs a restart, not `POST /v1/reload`.

## The service-account gotcha

**If you also run `marshal run` from automation as this same service user:** `--isolation
cgroup` and `--isolation netns` both go through `systemd-run --user`, which needs a running
*user* systemd instance for that account. An interactive login session has one; a bare service
account usually does not, unless lingering is enabled for it:

```bash
sudo loginctl enable-linger bot-marshal
```

Without that, `marshal run` fails outright rather than silently falling back to a weaker mode —
the same "fail loud, not quiet" choice made everywhere else identity is involved.

## Log rotation

`--audit-log` is append-only and never rotated by bot-marshal itself:

```
# /etc/logrotate.d/bot-marshal
/var/log/bot-marshal/audit.jsonl {
    daily
    rotate 30
    compress
    missingok
    copytruncate
}
```

`copytruncate` avoids needing to signal the process, which has no reopen handler.

## Upgrades

`POST /v1/reload` swaps configuration without dropping connections, but not the binary. For a
binary upgrade, `systemctl restart` — in-flight requests are dropped, so pick the moment.
Validate first:

```bash
sudo -u bot-marshal marshal --config /etc/bot-marshal/config.yaml config check && sudo systemctl restart bot-marshal
```
