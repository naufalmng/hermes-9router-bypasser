# STATE

Living status doc. Newest first. Everything here was verified by running it, not
by reading code.

Concrete patch intel (anchors, chunk names, byte offsets) is deliberately kept out
of this repository — it is the payload. See the private `FINDINGS.md`.

## 2026-10-22 — proven on real Windows (NAUFAL-DESKTOP)

The Linux run proved the protocol. This run proved the product, and it found four
bugs that Linux could never have shown.

Install layout on Windows is **not** `~/.hermes/hermes-agent`:

```
C:\Users\<user>\AppData\Local\hermes\hermes-agent      <- real install
```

`%LOCALAPPDATA%\hermes\hermes-agent`. The Linux layout still exists for portable
installs, so both must be probed, and a directory that merely has the right name
must not win over a real install (marker-file validation).

Bugs found and fixed:

1. **Every Hermes recipe reported `no_target` on Windows** — `{hermes_agent}`
   expanded to `~/.hermes/hermes-agent`, which does not exist there. Fixed with
   `HermesRoot()` discovery over both layouts, validated by marker files.
2. **9router recipes were Linux-only** (`platforms: ["linux"]`), so Windows
   customers got nothing. Chunk files are byte-identical across platforms for the
   same npm version, so the payload now lists linux/windows/darwin.
3. **A missing app failed the whole run** — a customer without 9router saw
   `5 failed` and exit 1. Now `skipped: 9router not installed`, exit 0. The
   distinction kept: app installed but file moved is still a reported failure.
4. **`h9b rollback` reported "nothing to roll back" on every Windows install** —
   it walked the hardcoded Linux path. It now resolves through `HermesRoot()`.

Proof, in order, on the real box:

```
stock            SOUL.md -> ['prompt_injection']    (scanned)
h9b apply        3 applied, 7 already, 0 failed
patched          SOUL.md -> []                       (bypassed)
                 notes.md -> ['prompt_injection']    (still scanned)
h9b rollback     restored 3 file(s), 0 failed
stock again      SOUL.md -> ['prompt_injection']
h9b apply        bypass back
```

`USER.md` and `random.txt` stay scanned in every state — the bypass is scoped to
the one filename, not global.

Also fixed: `make release` did not stamp `main.serverID`, so a release build would
have been a dev build that accepts payloads from any relay. `SERVERID` is now
required by the target and by CI (`H9B_SERVERID` secret); building without it
fails loudly instead of shipping an unauthenticated client.

## 2026-10-22 — deployed and proven through the public endpoint

```
https://h9b.apizen.my.id/healthz -> {"ok":true,"version":"0.1.0","bundle_version":1,"recipes":10}
```

Full cycle over the real internet, real tunnel, real client build:

```
h9bd cdk new -tier pro -days 30        -> H9B-QMWN9-...  lic_a9dc2a737bab
h9b activate (https://h9b.apizen.my.id) -> ok, bound to this machine
h9b apply                              -> 3 applied, 7 already, 0 failed
python3 scan_for_threats('SOUL.md')    -> []                      (trusted)
python3 scan_for_threats('notes.md')   -> ['prompt_injection']    (still scanned)
```

garble build verified: sensitive-string count 69 -> 1, symbol table empty,
binary 9.1 MB vs 5.5 MB plain (obfuscation costs size; worth it).

garble version trap: `go install mvdan.cc/garble@latest` builds a binary that
requires Go >= 1.27 and exits instantly on this box (Go 1.22.2). Pinned to
`v0.12.1` in the Makefile (`make garble-install`). The failure mode is nasty —
it overwrites the working binary, so the next release build silently fails.

### v0.18.0 evaluated and rejected (measured, not guessed)

Making v0.18.0 work needs a real GOROOT, not a toolchain module: garble patches
`src/cmd/link/internal/ld/pcln.go`, and Go refuses to overlay files under
GOMODCACHE (`overlay contains a replacement for .../toolchain@.../pcln.go`).
Copying the downloaded toolchain to `/opt/go1.27` and building with
`GOROOT=/opt/go1.27` does work — activate + apply both succeeded.

It is still the wrong choice:

| | v0.12.1 / Go 1.22 | v0.18.0 / Go 1.27 |
|---|---|---|
| binary | 9.09 MB | 18.35 MB |
| `ServerID`, `LicenseID`, `RecipeIDs` in `strings` | absent | **plaintext** |
| symbol table | empty | empty |
| extra toolchain to maintain | no | 253 MB GOROOT |

Newer garble leaks *more* here: Go 1.27's encoding/json reflection keeps the
struct field names as plain strings and garble no longer obfuscates them.
Staying on v0.12.1 — smaller and quieter.

Deployment choices worth remembering:

- **Second tunnel, not a new ingress rule.** `bojongkulur-edge` carries
  `ssh.apizen.my.id`; adding a hostname there needs a restart, and a restart can
  drop an in-flight SSH session. A dedicated `h9b` tunnel costs nothing.
- **Port 18090, not 8080.** 8080 is already held by docker-proxy on this box. The
  first deploy crash-looped on `bind: address already in use` before the switch.
- **`-token-key-file`, not `-token-key`.** The latter puts the HMAC key in `ps`
  output for every user on the box.
- **Store reloads on mtime.** `h9bd cdk new` while the server runs used to be
  invisible until restart, which reads to the customer as "your key is invalid".

## 2026-10-22 — framework scaffolded and proven end-to-end

### Proven by execution

```
activate      CDK -> token, bound to machine fingerprint            OK
payload       X25519 + HKDF + AES-GCM, decrypt in memory            OK
apply         dry-run: 3 applied, 7 already, 0 failed               OK
apply         real:    3 files written, backups created             OK
idempotent    second apply: 0 applied, 10 already, 0 failed         OK
rollback      3 files restored to stock, backups consumed           OK
re-apply      after rollback: 3 applied again                       OK
syntax        py_compile on all 3 patched files                     OK
behaviour     trusted file -> no findings                           OK
behaviour     ordinary file -> findings reported                    OK
```

The behavioural pair is the one that matters. The bypass is narrow on purpose: a
blanket `return []` would be easier to write, easier to detect, and would break
the scanner for every file instead of one class of file.

### Findings (public-safe summary)

1. **The earlier hand-rolled patch would have crashed.** It referenced a function
   argument that does not exist in the upstream signature, so the first scan would
   have raised `NameError`. Recipes now patch the signature and the body as one
   all-or-nothing unit.
2. **Two marker styles are in the wild** from two generations of the manual patch.
   Neither `detect` nor a re-run was safe with a single marker string, which is
   why `detect.contains_any` exists.
3. **Some targets were already patched** on the reference box and correctly report
   `already`. That is the right answer, not a failure — the distinction is what
   makes the hourly timer safe.
4. **Anchors drift between versions.** The generator diffs a pristine tarball
   against the installed tree rather than trusting hand-typed strings. When a
   version moves a construct, the generator reports `MISS` and refuses to emit.
5. **A `.bak` file in an install directory is not a reliable pristine reference.**
   It can come from a different version than the one installed.

### Design decisions worth keeping

- **Recipes are never committed.** Public repo ships the engine. This is the
  entire security model; every other control is secondary.
- **All-or-nothing per recipe.** A partial Python patch is worse than no patch:
  the install stops importing and the customer blames the tool.
- **CDKs are stored hashed.** The server cannot leak what it does not hold, and
  support can still identify a licence by mask.
- **Ephemeral X25519 per request.** The server discards its private key after
  sealing, so a later compromise of the store does not decrypt past payloads.
- **`if False and ...` over deletion** for the cron scan loops: the pattern tables
  stay intact, so the diff is four lines instead of four blocks.

### Known gaps

- CDK is not stored client-side → token rotation forces re-entry.
- No offline grace → server down means no apply.
- Windows fingerprint is `MachineGuid` only → cloned VMs collide.
- No Authenticode signing → SmartScreen warning on Windows.
- No `--verify` pass after write (no `py_compile` / `node --check`).
- No web dashboard. `h9bd lic list` is the dashboard.
- No payment integration. CDK issuance is manual until volume justifies otherwise.

## Undo

Nothing here touches a customer's machine until they run it. To revert the
reference box:

```bash
h9b rollback              # Hermes files
sudo h9b rollback --all   # + 9router chunks
```
