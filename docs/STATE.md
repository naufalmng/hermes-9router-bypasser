# STATE

Living status doc. Newest first. Everything here was verified by running it, not
by reading code.

Concrete patch intel (anchors, chunk names, byte offsets) is deliberately kept out
of this repository — it is the payload. See the private `FINDINGS.md`.

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
