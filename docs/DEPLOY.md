# Deployment

## Server (h9bd)

### Build

```bash
git clone <repo> /opt/hermes-9router-bypasser
cd /opt/hermes-9router-bypasser
make build          # bin/h9bd, bin/h9b
sudo install -m755 bin/h9bd /usr/local/bin/h9bd
```

### Secrets

Three files, all `chmod 600`, all outside the repo:

```bash
sudo mkdir -p /etc/h9b
# token signing key — rotate this and every customer token dies
openssl rand -hex 32 | sudo tee /etc/h9b/token.key >/dev/null
# server static X25519 identity (advertised in /v1/activate)
openssl rand -hex 32 | sudo tee /etc/h9b/server.key >/dev/null
# licence database
sudo mkdir -p /var/lib/h9b
```

### TLS

Behind Cloudflare / Caddy / nginx, terminate TLS there and run `h9bd` on
`127.0.0.1:8080` with `-tls-cert` unset:

```bash
h9bd serve -addr 127.0.0.1:8080 \
  -store /var/lib/h9b/store.json \
  -payloads /opt/hermes-9router-bypasser/payloads \
  -token-key "$(cat /etc/h9b/token.key)"
```

Direct TLS with a self-signed cert (works, pin handles trust):

```bash
h9bd cert new -host h9b.apizen.my.id -out /etc/h9b/tls
# prints the SPKI pin — put it in the client build:
#   make release PIN=<hex>
```

### systemd

```ini
# /etc/systemd/system/h9bd.service
[Unit]
Description=h9b licence and payload server
After=network-online.target

[Service]
Type=simple
User=h9b
Group=h9b
EnvironmentFile=/etc/h9b/env
ExecStart=/usr/local/bin/h9bd serve \
  -addr 127.0.0.1:8080 \
  -store /var/lib/h9b/store.json \
  -payloads /opt/hermes-9router-bypasser/payloads
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/h9b

[Install]
WantedBy=multi-user.target
```

`/etc/h9b/env`:

```
H9B_TOKEN_KEY=<hex from token.key>
```

The server accepts `-token-key` or `H9B_TOKEN_KEY`, whichever is set. There is no
default — it refuses to start without one, on purpose.

### DNS

```
h9b.apizen.my.id   A      <server IPv4>        proxied=yes (Cloudflare)
h9b.apizen.my.id   AAAA   <server IPv6>        proxied=yes
```

Client pins the certificate SPKI, so a Cloudflare proxy is fine — the pin follows
the origin cert, not the edge. If you later switch to Cloudflare's universal cert,
rebuild the client with the new pin, or ship both pins and accept either.

### Reload payloads without downtime

```bash
sudo kill -HUP $(pidof h9bd)
```

Recipes are re-read from `-payloads`; the licence store is untouched. This is how
a 9router version bump reaches customers in one command.

## Client (h9b)

### Release build

```bash
make release PIN=<spki-hex> VERSION=0.1.0
# dist/h9b-linux-amd64, h9b-linux-arm64, h9b-windows-amd64.exe, h9b-darwin-*
```

Requires `garble` (`go install mvdan.cc/garble@latest`). Without it `make build`
still works — you just get a non-obfuscated binary, which is fine for your own
machines and wrong for customers.

### Customer install

```bash
curl -fsSL https://h9b.apizen.my.id/i | sh
h9b activate H9B-XXXXX-XXXXX-XXXXX-XXX
h9b apply
```

The installer verifies the release SHA-256 before moving anything into place.

### Auto re-apply after `hermes update`

Linux (systemd user unit):

```bash
systemctl --user enable --now h9b-apply.timer
```

Windows (scheduled task, runs as the logged-in user):

```powershell
schtasks /create /tn h9b-apply /sc hourly /tr "%LOCALAPPDATA%\h9b\h9b.exe apply"
```

9router recipes need root (they write into `/usr/lib/node_modules`). Run those
with `sudo h9b apply --only r9-*`, or add a sudoers rule limited to `h9b`.

## Verification checklist before taking money

```bash
# 1. server answers
curl -s https://h9b.apizen.my.id/healthz

# 2. a key activates exactly once
h9b activate <cdk>
h9b activate <cdk>          # must fail: already bound

# 3. apply is idempotent
h9b apply && h9b apply      # second run: 0 applied, N already

# 4. rollback restores stock
h9b rollback && h9b apply

# 5. revoked key is rejected
h9bd cdk revoke <cdk> && h9b apply   # must fail with 403
```
