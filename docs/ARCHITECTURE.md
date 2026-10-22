# Architecture

## The one idea

**The patch logic never ships.**

Everything else is detail. A customer's machine must execute the patch, so the
patch is reachable by whoever owns the machine — that is physics, not a bug in
this design. What *is* controllable is **what they get when they reach it**:

| What ships | What stays on the server |
|---|---|
| a ~4 MB stripped Go binary that speaks one protocol | the recipes: which file, which anchor, which replacement |
| an X25519 public key and an SPKI pin | the token signing key, the licence database |
| a generic text-replacement engine (replace / regex / insert) | per-licence bundle selection, revocation, seat counting |

An attacker who fully reverses `h9b` learns: how to call an HTTPS endpoint, how
to do an ECDH handshake, and how to run `strings.Replace`. They do **not** learn
a single anchor, a single persona string, a single 9router chunk offset. To get
those they need a live licence, a live server, and a machine that is not
blacklisted — and what they capture is one bundle, for one licence, at one point
in time.

That is the moat. Obfuscation is the lock on the door; the payload split is the
reason there is nothing valuable behind it.

## Components

```
             ┌──────────────────────────────────────────────┐
   customer  │  h9b  (Go, garble-obfuscated, stripped)      │
             │  ├── fingerprint   3 hardware hashes         │
             │  ├── transport     TLS 1.3 + SPKI pin        │
             │  ├── handshake     X25519 eph-ephemeral      │
             │  ├── engine        replace/regex/insert      │
             │  └── state         ~/.h9b/config.json        │
             └───────────────┬──────────────────────────────┘
                             │  POST /v1/activate   (CDK + fp + hw)
                             │  POST /v1/payload    (token + fp + eph_pub)
                             ▼
             ┌──────────────────────────────────────────────┐
             │  h9bd  (Go, stdlib only)                     │
             │  ├── /v1/activate   CDK -> licence + token   │
             │  ├── /v1/payload    recipe bundle, sealed    │
             │  ├── /v1/report     drift telemetry          │
             │  └── store.json     licences, hashed CDKs    │
             └───────────────┬──────────────────────────────┘
                             │
             ┌───────────────▼──────────────────────────────┐
             │  payloads/*.json  (recipes, plaintext on     │
             │  the server only, sealed per request)        │
             └──────────────────────────────────────────────┘
```

## Wire protocol

### 1. Activation — once per machine

```
POST /v1/activate
{ "cdk": "H9B-XXXXX-XXXXX-XXXXX-XXX", "fp": "<16 hex>", "platform": "linux" }

200 { "license_id": "lic_...", "token": "<claims>.<hmac>", "expires_at": 1795..., "tier": "pro" }
409 { "error": "cdk already bound to another machine" }
404 { "error": "unknown or revoked cdk" }
```

The CDK is stored as `sha256(normalised_cdk)`. The plaintext key exists only in
the customer's inbox and in the response to `h9bd cdk new` — never in the
database. A stolen `store.json` is a list of hashes and machine IDs.

Binding is a 2-of-3 quorum over hardware components, not a single value:

```
machine   MachineGuid / machine-id / IOPlatformUUID
mac       sorted set of physical NIC addresses (virtual, bridge and tunnel excluded)
disk      serial or WWID of the physical disk backing / (walks LVM, LUKS, mdraid)
```

Two must match. A single component fails in both directions: MAC-only locks out
anyone who plugs in a dock or installs a VPN client, and machine-id-only is
worthless because the file is root-writable and travels with a cloned image.

The stored set is an **anchor**: it is written once, at first activation, and
never rewritten on tolerated drift. Refreshing it would let the binding walk —
swap the NIC (2/3), swap the disk (2/3 against the new set), swap the machine id
(2/3) — three accepted steps to completely different hardware. Two of three
components replaced therefore needs an operator `h9bd lic rebind`, which is the
point: it is the support lever.

Each component is stored as `sha256(pepper ‖ name ‖ raw)`. Raw MACs and serials
never leave the machine, and the pepper (a release secret, stable across all
versions) stops a leaked store from being brute-forced back into MAC addresses.

### 2. Payload — every run

```
POST /v1/payload
{ "token": "...", "fp": "...", "eph_pub": "<b64 X25519>", "nonce": "<b64 16B>" }

200 { "server_eph_pub": "<b64>", "nonce": "<b64 12B>", "ct": "<b64 AES-256-GCM>",
      "server_id": "<b64 Ed25519 pub>", "sig": "<b64 Ed25519>",
      "expires_at": ..., "bundle_id": "bundle-20261022" }
```

Key agreement, per request:

```
shared  = X25519(server_eph_priv, client_eph_pub)
salt    = SHA256(nonce_b64 || license_id)
key     = HKDF-SHA256(shared, salt, "h9b-payload-v1", 32)
plain   = AES-256-GCM-Open(key, nonce, ct)
```

Properties worth naming:

- **Forward secrecy.** `server_eph_priv` is generated per request and dropped.
  Compromising the server tomorrow does not decrypt a capture from today.
- **No static payload key.** There is no key in the binary to extract, because
  the key does not exist until the handshake completes.
- **Binding.** `salt` includes the licence id and the client nonce, so a response
  cannot be replayed to a different licence or a different request.

### 2b. Why the signature, and not just TLS pinning

Pinning is only as good as the certificate, and the certificate stops being yours
the moment the server sits behind a tunnel or proxy: Cloudflare, a corporate
middlebox, a cheap VPS with its own terminator. In that topology an interceptor
completes the X25519 handshake with **its own** ephemeral key, seals **its own**
payload, and the client decrypts it happily — pinning never fires, because TLS was
legitimately terminated upstream.

So the payload channel authenticates itself, independent of TLS:

```
server holds   Ed25519 identity key (never leaves the box)
client embeds  the matching public key at build time (-X main.serverID=...)

transcript = "h9b/v1|" + license_id + "|" + client_eph_pub
                       + "|" + server_eph_pub + "|" + request_nonce

response carries  server_id, sig = Ed25519(transcript)
client            verifies sig BEFORE deriving the content key
```

Every field the client is about to act on is inside the transcript: swap the
licence, the client key, the server key or the nonce and the signature breaks. A
relay cannot sign, so it can only forward the real response verbatim — a delivery,
not an attack.

Consequence: **pinning is defence-in-depth, not the load-bearing control**, and
the product runs behind Cloudflare Tunnel without weakening. The identity key is
generated once and backed up like a signing key; rotating it invalidates every
shipped client.

The bundle is decrypted into memory, applied, and dropped. Nothing hits disk
except the files being patched (which are the customer's own files) and their
`.h9b-<ts>` backups.

### 3. Report — after every apply

```
POST /v1/report
{ "token": ..., "bundle_id": ..., "results": [ {"id":"r9-mimo-free","status":"missing_anchor"} ] }
```

This is the anchor-drift alarm. When 9router ships 0.6.0 and every `find` string
moves, the operator sees it in `h9bd lic list` before a single customer emails.

## The recipe engine

A recipe is data, not code:

```json
{
  "id": "hg-threat-patterns",
  "target": { "kind": "python_file", "path": "{hermes_agent}/tools/threat_patterns.py" },
  "detect": { "contains_any": ["# [H9B]", "SOME-OLDER-MARKER"] },
  "ops": [
    { "op": "replace", "find": "...", "with": "...", "count": 1, "required": true }
  ]
}
```

Operations: `replace` (literal, count-limited), `regex_replace`, `insert_after`,
`append`.

Rules that keep it safe on a stranger's machine:

1. **All-or-nothing per recipe.** If a `required` op misses, the file is not
   written at all. No half-patched Python that fails to import.
2. **`detect` first.** A marker means "already applied, do not touch". This is
   what makes `apply` idempotent and safe to run from cron.
3. **Backup before write.** `file.h9b-YYYYMMDD-HHMMSS`, mode preserved.
4. **Path placeholders resolve on the client.** `{hermes_agent}`, `{home}`,
   `{router9_chunks}`. One bundle, every OS and prefix.
5. **Platform gate.** A `linux`-only recipe is skipped on Windows, not failed.

## Why the recipes are generated, not hand-written

`tools/build_router9_payload.py` diffs a pristine `npm pack` tarball against the
patched install and emits `find`/`with` pairs from the actual bytes. Hand-copied
anchors rot silently; generated ones cannot drift from what was verified.

`tools/build_hermes_payload.py` holds hand-verified anchors because the Hermes
source is small and stable, but it fixed two real bugs from the earlier
hand-rolled script: the missing `filename` parameter on `scan_for_threats()`
(which made the old patch raise `NameError`) and non-idempotent double-patching
across two marker styles.

## Update resilience

The customer's pain is that `hermes update` restores guardrails. Two answers:

- `h9b watch --interval 60` re-applies when a watched file's hash changes.
- A systemd user unit / scheduled task runs `h9b apply` at boot and hourly.

Because the bundle is fetched fresh each run, a recipe fix reaches every customer
without them reinstalling anything.
