# hermes-9router-bypasser

**h9b** — runtime patch distribution with licence keys.

Patch Hermes Agent and 9router on a customer machine from one command, without
shipping the patch. Recipes live on the server, sealed per request to a licence
and a machine, and are applied in memory.

```
curl -fsSL https://h9b.apizen.my.id/i | sh
h9b activate H9B-XXXXX-XXXXX-XXXXX-XXX
h9b apply
```

---

## Bahasa Indonesia

### Ini apa

Sistem distribusi patch untuk **Hermes Agent** dan **9router** yang dikontrol
lewat CDK (licence key). Pelanggan install satu binary, masukin CDK, dan patch
jalan otomatis — termasuk **apply ulang sendiri setelah `hermes update`**.

Yang penting: **logika patch-nya nggak pernah ikut dikirim.** Binary klien cuma
tahu cara minta payload, bukan isi payload-nya. Jadi walaupun di-reverse, yang
didapat cuma protokol — bukan anchor, bukan string, bukan offset chunk 9router.

### Kenapa dibikin

Kerjaan patch manual tadi punya tiga masalah nyata:

1. **Nggak idempotent.** Dijalanin dua kali, file ke-patch dua kali.
2. **Salah anchor = file rusak.** Patch lama bahkan nambah `filename` ke
   `scan_for_threats()` tanpa ngubah signature-nya → `NameError` pas runtime.
3. **Hilang tiap update.** `hermes update` balikin guardrail, dan tiap rilis
   9router anchor-nya geser.

h9b jawab ketiganya: `detect` bikin idempotent, semua-atau-tidak-sama-sekali
per resep (nggak ada file setengah jadi), dan `h9b watch` / systemd timer
nge-apply ulang otomatis.

### Arsitektur singkat

| Lapisan | Isi | Ada di mana |
|---|---|---|
| Klien | 4 MB Go, garble-obfuscated, stripped | mesin pelanggan |
| Transport | TLS 1.3 + SPKI pin | keduanya |
| Kunci payload | X25519 ephemeral per request + HKDF + AES-256-GCM | negosiasi |
| Resep | anchor + replacement (JSON) | **server saja** |
| Lisensi | CDK → hash → ikatan fingerprint | server saja |

Detail lengkap: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Ancaman dan batasannya: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) —
**baca ini sebelum jualan**, ada daftar gap yang jujur.

### Yang dilindungi

- `SOUL.md` / `SKILL.md` / `AGENTS.md` dimuat apa adanya (nggak discan)
- scan memori, scan cron prompt, scan skill install dimatikan
- 9router: persona CodeBuddy / MiMo dibuang, `safetySettings` dipaksa off

### Perintah

```bash
h9b activate H9B-...        # ikat ke mesin ini (sekali)
h9b apply                   # ambil + terapkan
h9b apply --dry-run -v      # lihat dulu, nggak nulis
h9b status                  # lisensi + file yang kena
h9b doctor                  # diagnosa: server, pin, fingerprint, target
h9b rollback                # balikin ke stock (backup .h9b-<ts>)
h9b watch --interval 60     # apply ulang otomatis
```

Sisi operator:

```bash
h9bd cdk new -n 10 -tier pro -days 30 -note "batch-11"
h9bd lic list
h9bd lic show lic_xxxx
h9bd cdk revoke -cdk H9B-...
h9bd lic rebind lic_xxxx     # pelanggan ganti mesin
h9bd payload check -dir ./payloads
kill -HUP $(pidof h9bd)      # reload resep tanpa downtime
```

### Build

```bash
make build                          # binary biasa (buat mesin sendiri)
make payload R9VER=0.5.95           # regenerate resep dari tarball pristine
make release PIN=<spki> VERSION=0.1.0   # cross-compile + garble + SHA256SUMS
```

`make release` butuh `garble`:

```bash
go install mvdan.cc/garble@latest
```

### Deploy

[docs/DEPLOY.md](docs/DEPLOY.md) — systemd unit, TLS, DNS `h9b.apizen.my.id`,
scheduled task Windows, dan checklist verifikasi sebelum nagih duit.

---

## English

### What this is

Licence-gated patch distribution for **Hermes Agent** and **9router**. The
customer installs one binary, enters a CDK, and patches apply automatically —
including **re-applying after `hermes update` wipes them**.

The design constraint: **the patch logic never ships.** The client knows how to
ask for a payload, not what is in it. Reversing the binary yields the protocol
and a generic text-replacement engine — no anchors, no persona strings, no 9router
chunk offsets.

### Why

The manual patching workflow had three real defects:

1. **Not idempotent** — running it twice double-patched files.
2. **A bad anchor corrupts the file** — the earlier script added a `filename`
   argument to `scan_for_threats()` without changing the signature, which raises
   `NameError` at runtime.
3. **Lost on every update** — `hermes update` restores guardrails, and 9router
   moves its anchors every release.

h9b fixes all three: `detect` markers make apply idempotent, each recipe is
all-or-nothing so a missed anchor never writes a half-patched file, and
`h9b watch` / a systemd timer re-applies on drift.

### Layout

```
cmd/h9b        customer CLI (garble-obfuscated on release)
cmd/h9bd       licence + payload server (stdlib only, no cgo)
internal/kdf   HKDF-SHA256 + AES-256-GCM
internal/cdk   Crockford base32 keys with checksum
internal/store JSON licence store, CDKs kept hashed
internal/recipe  recipe schema + patch engine
payloads/      schema example ONLY — real recipes are server-side, not in this repo
tools/         recipe generators, run at authoring time
docs/          architecture, threat model, CDK lifecycle, deployment
```

> **The real recipes are not in this repository, by design.** Publishing them
> would hand out the payload and make the CDK pointless. This repo ships the
> engine; the anchors live on the licence server. See
> [payloads/README.md](payloads/README.md).

### Security posture

Read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). The short version:

- A customer who reverses the binary gets nothing to unlock — payloads are
  server-side and sealed to a live licence.
- A customer who buys a licence and dumps the decrypted bundle gets one stale
  snapshot of recipe data. That is the accepted, documented trade-off.
- What is *not* defended, and why, is listed explicitly in that document.

### License

GPL-3.0. See [LICENSE](LICENSE).

Author: **F1Nah601** · Brand: OPA / Opalabs
