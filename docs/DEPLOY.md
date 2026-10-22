# Deployment

## Live instance

```
https://h9b.apizen.my.id        Cloudflare tunnel -> 127.0.0.1:18090
```

Server: `h9bd.service` at `/opt/h9b`, payloads in `/opt/h9b/payloads`, identity
key in `/opt/h9b/data/server.ed25519`.

## One run per machine, then it is done

There is **no timer and no daemon on the customer side**. `h9b apply` is a single
one-shot run that ends with a verification pass, and the last line answers the
only question the customer has:

```
verifikasi
  ok   hg-threat-patterns             
  ok   hg-cron-scan                   
  ok   r9-codebuddy-cn                

SELESAI — 10/10 terverifikasi
```

Exit code 0 means verified, non-zero means not done. If something is wrong the
line reads `BELUM SELESAI — 2/10 gagal: hg-cron-scan, r9-mimo-free` and the
per-recipe reason is printed above it.

What each target is checked for:

- **marker** — the replacement text is actually in the file (the patch landed)
- **syntax** — the file still parses with its own interpreter (`python -c compile`
  for `.py`, `node --check` for `.js`), using the venv next to the Hermes install
  so the check runs on the interpreter that will actually import the file

Nothing is written by the verification pass: the Python check compiles the bytes
in memory instead of `py_compile`, so no `__pycache__` appears in the customer's
tree.

`h9b apply --dry-run` shows what would change and skips verification.
`h9b apply --no-verify` writes without checking — for debugging only.

If Hermes is later updated and the patch is reverted, the customer runs
`h9b apply` again. It is idempotent: already-patched targets report `already`.

## Tiers

| tier flag | product | recipes received |
|---|---|---|
| `basic-hermes` | Basic | `hg-*` only |
| `basic-router9` | Basic | `r9-*` only |
| `pro` | Pro | both |

Filtering happens on the **server**, before encryption. A Basic customer who dumps
the client's memory finds only the recipes they paid for. Bare `basic` is refused
because it names two products.

## Selling: manual, by CLI

Payment is confirmed by hand, then the operator issues the key:

```sh
h9bd cdk new -tier pro -days 30 -note "ORDER-1234 @buyer" -store /opt/h9b/data/store.json
# H9B-XXXXX-XXXXX-XXXXX-XXX   lic_xxxxxxxxxxxx   pro   Pro (Hermes+9router)   expires 2026-11-21
```

Renewal:

```sh
h9bd lic extend lic_xxxxxxxxxxxx -days 30
```

Extend counts from `max(now, current expiry)`, so renewing early does not burn the
days already paid for. Support actions:

```sh
h9bd lic list
h9bd lic show lic_xxxxxxxxxxxx      # full record incl. last apply report
h9bd lic note lic_xxxxxxxxxxxx "ORDER-1234 paid 2026-10-22"
h9bd lic rebind lic_xxxxxxxxxxxx    # customer changed machine
h9bd lic revoke lic_xxxxxxxxxxxx    # chargeback / leak
```

## Install on a customer machine

The entry point is the **public repository**, not our server. The script is
harmless to publish: it only downloads a binary and runs it. All patch logic,
anchors and offsets stay server-side.

```sh
curl -fsSL https://raw.githubusercontent.com/naufalmng/hermes-9router-bypasser/master/install.sh | sh
h9b activate H9B-XXXXX-XXXXX-XXXXX-XXX
h9b apply --dry-run --verbose     # look before you write
h9b apply
```

No-install variant — the binary is fetched to a temp dir, run, and deleted. Only
`~/.h9b/config.json` (the licence) survives, so the calls can be separated:

```sh
curl -fsSL https://raw.githubusercontent.com/naufalmng/hermes-9router-bypasser/master/install.sh | sh -s -- activate H9B-XXXXX-XXXXX-XXXXX-XXX
curl -fsSL https://raw.githubusercontent.com/naufalmng/hermes-9router-bypasser/master/install.sh | sh -s -- apply
```

The installer verifies `SHA256SUMS` and refuses to run a mismatched binary.

### Windows

```powershell
iwr -useb https://raw.githubusercontent.com/naufalmng/hermes-9router-bypasser/master/install.ps1 | iex
$env:H9B_ARGS="activate H9B-XXXXX-XXXXX-XXXXX-XXX"; iwr -useb https://raw.githubusercontent.com/naufalmng/hermes-9router-bypasser/master/install.ps1 | iex
$env:H9B_ARGS="apply"; iwr -useb https://raw.githubusercontent.com/naufalmng/hermes-9router-bypasser/master/install.ps1 | iex
```

`install.ps1` pins TLS 1.2 (Windows PowerShell 5.1 still defaults to TLS 1.0 on
some builds, and the handshake then fails with a useless "underlying connection
was closed") and calls `Unblock-File` before executing.

### Binaries are served by us, not GitHub

`h9bd -assets /opt/h9b/assets` serves the release files at `/dl/<name>`. The
installer tries that mirror first and falls back to GitHub releases only if it
fails.

This is not cosmetic. GitHub's asset CDN repeatedly established a connection and
then delivered nothing from an Indonesian consumer link — the one-liner sat with
no output at all, and `--max-time` alone took minutes to give up. The same 9 MB
file comes off our tunnel in ~3 s. Populate the directory after every release:

```sh
cp dist/h9b-* dist/h9bd-* dist/SHA256SUMS dist/install.sh /opt/h9b/assets/
```

Only `h9b-*`, `h9bd-*`, `SHA256SUMS` and `install.sh` are exposed; the handler
takes `path.Base` and then checks that whitelist, so `/dl/../../etc/passwd` is a
404 rather than a file read. `/i` still exists as a convenience alias but is no
longer what customers are told to use.

### Windows install layout

The install layout is **not** `~/.hermes/hermes-agent`:

```
%LOCALAPPDATA%\hermes\hermes-agent     e.g. C:\Users\<user>\AppData\Local\hermes\hermes-agent
```

`h9b` probes both layouts and validates with marker files (`tools/threat_patterns.py`,
`agent/prompt_builder.py`), so a stray directory with the right name cannot win.
Override with `H9B_HERMES_ROOT` when a customer has an unusual prefix.

A missing 9router is reported as `skipped: 9router not installed` and does **not**
fail the run. A missing file inside an installed app is a real failure and does.

## Build a release

```sh
make garble-install                                   # pinned v0.12.1
make release SERVERID=<b64-ed25519-pub> PEPPER=<stable-secret> VERSION=0.2.0
```

Targets: `linux/amd64`, `linux/arm64`, `windows/amd64`. macOS is not built.

`SERVERID` is mandatory: without it the client is a dev build that warns and does
not authenticate the server, which would let a relay hand out its own payloads.

`PEPPER` is mandatory and **must never change**: every hardware component is
hashed with it, so rotating it makes every bound licence stop matching its own
machine until each customer rebinds. Keep it in the release secret
(`H9B_PEPPER`) and in `/opt/h9b-secrets/pepper.txt` on the operator machine.
The default in source is a public placeholder; a leaked store hashed with it
could be brute-forced back into customer MAC addresses.

## Server (h9bd) from scratch
