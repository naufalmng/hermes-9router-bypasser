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

## 2026-10-22 — hardware lock: 2-of-3 quorum over machine, MAC, disk

A single-value binding was wrong in both directions, so it is now three
components with a quorum:

```
machine   Windows MachineGuid        Linux /etc/machine-id
mac       Get-NetAdapter -Physical   /sys/class/net/*/address (physical only)
disk      Win32_DiskDrive serial     physical disk serial/WWID (walks LVM/LUKS/md)
```

Two of three must match. Hashing only the MAC locks out a customer who plugs in a
dock or installs a VPN client; hashing only machine-id is worthless because that
file is root-writable and travels with a cloned image — the exact sharing the lock
exists to stop.

**The stored set is an anchor, not a snapshot.** The first implementation
refreshed it on tolerated drift, which is a slow-motion bypass: swap the NIC
(2/3, accept), swap the disk (2/3 against the refreshed set, accept), swap the
machine id (2/3, accept) — the licence has now walked onto unrelated hardware one
component at a time. It never refreshes now, so every comparison is against the
box the licence was sold for. Two of three components replaced needs an operator
`h9bd lic rebind`.

### Proven against the live endpoint

A Python replay of `/v1/activate` (same peppered hashing, verified by reproducing
the binary's composite exactly) with a real issued key:

```
ALLOW  200  all three match                       pro
ALLOW  200  nic swapped (2/3)                     pro
ALLOW  200  disk swapped (2/3)                    pro
REFUSE 403  only machine-id (1/3) — cloned image  bound_elsewhere
REFUSE 403  nothing matches (0/3)                 bound_elsewhere
```

Drift walk, same key:

```
PASS  200  bind real hardware
PASS  200  nic swapped
PASS  403  nic + disk swapped          <- anchor held
PASS  403  entirely new box
PASS  200  real hardware again
```

A Windows-bound licence used from this Linux box:

```
REFUSED 403 licence bound to another machine (0/3 hardware components matched, 2 required)
```

### Bugs this round

8. **Disk component vanished on LVM/LUKS.** `filepath.Base(findmnt SOURCE /)` is
   `ubuntu--vg-ubuntu--lv`, which has no `/sys/block` entry, so the component was
   silently dropped and the box bound on 2 of 3. Now walks the device stack with
   `lsblk -s` (fallback: `/sys/class/block/*/slaves`) down to the physical disk,
   then reads `device/serial` → `serial` → `device/wwid` → `wwid`.
9. **`lsblk -sno` still emits tree glyphs** (`└─sda`), so the parsed name never
   matched `/sys/block`. Needs `-r` (raw).
10. **Anchor refresh enabled the drift walk** described above.
11. **Pepper was the public default `h9b-dev-pepper`.** A leaked store would have
    been brute-forceable back to customer MAC addresses (2^48 space). Release now
    requires `PEPPER` and refuses to build without it; the value lives in
    `/opt/h9b-secrets/pepper.txt` and must never rotate without a mass rebind.
    Because this changed every hash, all existing licences were rebound.
12. **`-X` left the pepper in plaintext.** Stamping it with `-X` writes the raw
    bytes into the symbol table, so `strings h9b | grep <pepper>` recovered it in
    one command and garble could not help. Release now generates
    `internal/fingerprint/pepper_gen.go` (build tag `pepperbuild`) with the value
    as a string *literal*, which garble's `-literals` pass stores encrypted.
    Verified: `grep -c <pepper> dist/h9b-*` → 0 on both binaries, and the
    composite fingerprint is unchanged (`437d592e…`), so no customer rebind.
13. **`lic list` showed the wrong columns.** The hardware column landed in
    `cdk list` instead (two `case "list"` blocks, one per subcommand), and the
    state label defaulted to `unbound` for bound licences. Now `lic list` prints
    `APPLY  HW  BOUND / STATE` with the component count, and `cdk list` stays a
    simple issued-key view.
14. **The installer could hang forever.** No `--connect-timeout`/`--max-time`, so
    a stalled GitHub asset CDN produced a completely silent hang — reproduced
    live while testing the public one-liner. Now 20 s connect, 300 s total,
    3 retries.
15. **`healthz` reported `0.1.0` on a 0.2.0 server.** `serverVersion` was a
    `const`, which is inlined and cannot be set by `-X`; it is a `var` now and the
    release stamps it.

Windows after the change reports all three components and still applies cleanly:

```
hw disk 299ce22e   hw mac d04c0ce0   hw machine c7756f23   hw quorum 2 of 3 required
bundle bundle-20261022 v1 — 0 applied, 5 already, 5 skipped, 0 failed
SELESAI — 5/5 terverifikasi      exit 0
```

## 2026-10-22 — tiers, one-shot verification, Windows+Linux only

Product decisions from the owner, all four implemented:

**1. Targets are Windows and Linux only.** `darwin/amd64` and `darwin/arm64` are
gone from `TARGETS`. The 9router chunks live in a Homebrew prefix that differs per
machine, and a target nobody tested is how a customer ends up with a silent no-op.

**2. Three tiers, enforced on the server.**

```
basic-hermes    hg-* only     proven: 5 hg, 0 r9
basic-router9   r9-* only     proven: 0 hg, 5 r9
pro             both          proven: 5 hg, 5 r9
```

`internal/tier` maps recipe prefix to product, and `handlePayload` filters before
sealing. A Basic customer who dumps the client's memory finds only the recipes
they paid for. Bare `basic` is refused — it names two products, and guessing
sells the wrong half. Unknown tier strings fail closed.

**3. Selling is manual by CLI.** `cdk new -tier … -note "ORDER-1234"`, then
`lic extend -days N` on renewal. Extend counts from `max(now, current expiry)` so
renewing early does not burn paid days. Also added `lic note` for order refs.

**4. No timer, no daemon on the customer machine.** `h9b watch` and the systemd
timer are deleted. One run per machine, and the run ends with a verification pass
that answers the only question the customer has:

```
verifikasi
  ok   hg-threat-patterns
  ...
SELESAI — 10/10 terverifikasi      exit 0
BELUM SELESAI — 1/10 gagal: hg-threat-patterns   exit 1
```

Each target is proven twice: **marker** (replacement text present in the file) and
**syntax** (file still parses with its own interpreter — `python -c compile` using
the venv next to the install, `node --check` for `.js`). Nothing is written by the
check: the Python path compiles bytes in memory, so no `__pycache__` appears in
the customer's tree.

Proven on this box: apply → `SELESAI 10/10`; corrupt a file → `BELUM SELESAI 1/10`
exit 1; `rollback` → file parses again.

### Bugs this round

5. **`-days` after a positional was silently dropped.** `h9bd lic extend lic_xxx
   -days 30 -store …` ignored both flags, opened the default store (empty in a
   fresh cwd) and reported "no licence matching". Added `reorderFlags`, which
   reads each flag's arity from the FlagSet so both orders work.
6. **`findPython` only looked for `python.exe`.** On Linux the venv check then
   fell through to the system python — a different interpreter than the one that
   imports the file. Now platform-aware (`python3`/`python` vs `*.exe`).
7. **skipped counted as already.** A customer without 9router saw "10 already"
   when 5 were skipped. Now the summary separates them:
   `0 applied, 5 already, 5 skipped, 0 failed`.

Windows re-proven after the change: `basic-hermes` key → 5 recipes, `SELESAI 5/5`;
`pro` key → 10 recipes, 5 skipped (no 9router), `SELESAI 5/5`, exit 0.

Linux, using the published release binary rather than a dev build:

```
apply   3 applied, 7 already, 0 skipped, 0 failed
verifikasi
  ok   hg-threat-patterns ... r9-gemini-safety-2
SELESAI — 10/10 terverifikasi      exit 0
rollback  restored 3 file(s), 0 failed
```

The three files were restored to stock afterwards, so this box is left exactly as
it was found.

### Published

`v0.1.0` on GitHub with 4 assets + `install.sh`. The customer path is proven end
to end:

```
curl -fsSL https://github.com/naufalmng/hermes-9router-bypasser/releases/latest/download/install.sh | sh
  fetching h9b-linux-amd64 (latest)
  checksum ok
  installed -> ~/.local/bin/h9b
```

`install.sh` had to be added as a release asset — the README pointed at
`releases/latest/download/install.sh`, which 404s unless it is uploaded. The
workflow now includes it.

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
