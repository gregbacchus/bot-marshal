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
# tls.ca_cert / tls.ca_key in marshal.yaml should point under /var/lib/bot-marshal
sudo -u bot-marshal marshal --config /etc/bot-marshal/marshal.yaml ca init
```

## systemd unit

```ini
# /etc/systemd/system/bot-marshal.service
[Unit]
Description=bot-marshal egress proxy
After=network.target

[Service]
User=bot-marshal
Group=bot-marshal
ExecStart=/usr/local/bin/marshal --config /etc/bot-marshal/marshal.yaml serve
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
├── marshal.yaml
├── profiles/
├── bundles/
└── transforms/
/var/lib/bot-marshal/
├── ca.crt
└── ca.key          # mode 0600 — whoever holds this can impersonate every site
```

Secret files a `file`-type source points at belong here too, readable only by the service user.

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
marshal --config /etc/bot-marshal/marshal.yaml config check && sudo systemctl restart bot-marshal
```
