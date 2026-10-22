# Threat model

Honest version. The goal is not "impossible to reverse" — that does not exist for
software that runs on someone else's machine. The goal is **cost asymmetry**: make
the cheapest attack more expensive than the CDK.

## Attacker classes

### A1 — Curious customer (most common)

Has the binary, has `strings`, maybe has Ghidra open on a rainy day.

*Wants:* remove the licence check, share the binary with a friend.

*Gets:* a garble-obfuscated binary with literal strings encrypted and control flow
flattened. `strings h9b | grep -i h9b` returns nothing useful. Patching the licence
check yields a client that still cannot produce a payload — the recipes live on the
server and are sealed to a live licence.

*Cost to win:* they cannot. There is nothing local to unlock.

### A2 — Reseller (the one that actually hurts)

Buys one CDK, sells "installations" to twenty people.

*Gets:* one CDK binds one fingerprint. Second machine gets `409 cdk already bound`.
Even if they share the token, `/v1/payload` compares `fp` against the bound value
and rejects. Heartbeat `last_seen` per licence exposes a machine that changes
fingerprint more than once a week.

*Cost to win:* one CDK per machine, i.e. they become a customer.

### A3 — Reverse engineer with a live licence

The real threat. They buy a CDK, run `h9b apply`, and dump the decrypted bundle.

*Gets:* **one** bundle snapshot. That is unavoidable and it is fine, because:

- the snapshot is recipe *data* (anchors + replacement text) for one 9router
  version and one Hermes version — it is stale within weeks;
- it contains no signing key, no server key, no CDK database, no way to mint
  licences;
- re-distributing it means re-distributing a text-diff service, which is exactly
  the product they were avoiding paying for.

*Cost to win:* they must redo the diff on every upstream release, forever. That is
the labour the CDK pays for. Most people who can do that will not bother, and the
ones who do are not customers anyway.

### A4 — Server attacker

Wants the recipe store or the token key.

*Gets:* TLS 1.3 + SPKI pin on the client, no admin endpoints over HTTP at all
(CDK issuance is a local CLI command), token key from a file or env with no default,
`store.json` holding only `sha256(cdk)`.

*Wins only if:* they get shell on the server. Then they get today's recipes and
can mint tokens. Response: rotate `-token-key` (invalidates every token, customers
re-activate automatically on next `apply` with their stored CDK... which is not
stored — see *Known gaps*).

## What is deliberately NOT defended

| Vector | Why it is out of scope |
|---|---|
| Customer patching their own binary to skip activation | They still get no payload. Pointless attack, not worth code. |
| Memory dump during `apply` (`gcore`, `/proc/pid/mem`) | Same yield as A3. Only mitigable with a kernel driver, which breaks portability. |
| Screenshot of the recipe JSON | Data has to be readable to be applied. |
| Customer running the patch by hand after seeing it once | They paid for the CDK; the diff is theirs. |
| Root on the customer machine | Root can do anything. Out of scope by definition. |

## Controls actually implemented

| Layer | Control | File |
|---|---|---|
| Build | garble `-tiny -literals`, `-trimpath`, `-s -w`, no DWARF | `Makefile` |
| Transport | TLS 1.3, SPKI SHA-256 pin compiled in, optional private CA | `cmd/h9b/main.go` |
| Crypto | per-request X25519 ephemeral, HKDF-SHA256, AES-256-GCM | `internal/kdf` |
| Licence | CDK bound to machine fingerprint, one-shot | `internal/store` |
| Token | HMAC-SHA256, carries `lid`+`fp`+`exp`, verified per request | `internal/token` |
| Replay | server-issued nonce, client nonce in KDF salt | `cmd/h9bd` |
| Rate limit | min 3 s between payload fetches per fingerprint | `cmd/h9bd` |
| Revocation | `h9bd cdk revoke`, checked on every request | `internal/store` |
| Least data | CDK stored hashed; no plaintext keys at rest | `internal/store` |
| Anti-drift | per-recipe result reporting | `/v1/report` |

## Known gaps (read this before selling)

1. **The CDK is not stored on the client.** `~/.h9b/config.json` holds the token
   only. If the token key is rotated the customer must re-enter the CDK. Fix:
   store the CDK encrypted under the machine fingerprint, or issue long-lived
   tokens and rotate by grace period.
2. **No offline grace.** Server down = no apply. Acceptable for a patch service,
   but a customer mid-`hermes update` will notice. Fix: cache the last bundle,
   encrypted, with a 24 h TTL.
3. **Windows fingerprint** uses `MachineGuid` from the registry. Cloned VM images
   share it. Fix: mix in the volume serial of `C:`.
4. **No code signing** on the Windows binary. SmartScreen will complain. Fix:
   Authenticode certificate, ~$100/yr, worth it before charging money.
5. **Single server.** No HA. Fine at this scale; note it in the SLA.
