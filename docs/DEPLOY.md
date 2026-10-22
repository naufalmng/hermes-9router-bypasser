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

```sh
curl -fsSL https://github.com/naufalmng/hermes-9router-bypasser/releases/latest/download/install.sh | sh
h9b activate H9B-XXXXX-XXXXX-XXXXX-XXX
h9b apply --dry-run --verbose     # look before you write
h9b apply
```

The installer verifies `SHA256SUMS` and refuses to install a mismatched binary.

### Windows

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
make release SERVERID=<b64-ed25519-pub> VERSION=0.1.0
```

Targets: `linux/amd64`, `linux/arm64`, `windows/amd64`. macOS is not built.

`SERVERID` is mandatory: without it the client is a dev build that warns and does
not authenticate the server, which would let a relay hand out its own payloads.

## Server (h9bd) from scratch
