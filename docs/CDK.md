# CDK format and lifecycle

## Format

```
H9B-XXXXX-XXXXX-XXXXX-XXX
```

- `16` data characters — 10 random bytes, Crockford base32 (no `I`, `L`, `O`, `U`).
- `2` check characters — first 8 bits of `SHA-256(data)`, same alphabet.
- Prefix and dashes are cosmetic; validation normalises them away, so a customer
  can paste `h9bxxxxx...` or with spaces and it still works.

Crockford base32 is used because it survives being read aloud and typed by hand:
`0/O` and `1/I/L` cannot be confused, and the alphabet has no `U` to accidentally
spell anything.

A 10-byte body is 2^80 keyspace. Guessing is not a threat model at this volume;
the rate limit and the per-fingerprint binding are what matter.

Example (throwaway, generated for this document):

```
H9B-R71V4-VQM88-RA1C3-NJM
```

## Lifecycle

```
        h9bd cdk new -n 10 -tier pro -days 30 -note "batch 2026-11"
                              │
                              ▼
                     store.json: sha256(cdk) -> licence, unbound
                              │
             customer runs `h9b activate <cdk>` on machine M
                              ▼
                     licence.fp = fp(M)      <- one-shot bind
                              │
             every `h9b apply` -> /v1/payload -> verify fp, revoke, expiry
                              ▼
             operator `h9bd cdk revoke <cdk>` -> 403 on next request
```

## Operator commands

```bash
# issue 10 keys, 30-day licences, pro tier, with a note you will thank yourself for
h9bd cdk new -store /var/lib/h9b/store.json -n 10 -tier pro -days 30 -note "batch-2026-11"

# who has what
h9bd lic list -store /var/lib/h9b/store.json

# kill a leaked key
h9bd cdk revoke -store /var/lib/h9b/store.json H9B-R71V4-VQM88-RA1C3-NJM

# move a licence to a re-imaged machine
h9bd lic rebind -store /var/lib/h9b/store.json lic_56e808afad62
```

`h9bd cdk new` prints the plaintext keys **once**. They are not recoverable from
the store — only the hash is kept. Redirect to a file with `> keys.txt` and treat
that file as a secret.

## Tiers

`tier` is carried in the token and recorded on the licence. It is not enforced by
the current payload selector — every licence gets every recipe. When you need
segmentation, filter in `cmd/h9bd`'s payload handler on `lic.Tier`; the field is
already plumbed through activation, token, and store.

## Expiry

`expires_at` is checked on every `/v1/payload`. An expired licence gets `403`,
and `h9b apply` reports `licence expired — renew` instead of a crypto error, so
the customer knows what to buy rather than filing a bug.

## What a leaked CDK gives an attacker

One bound machine's worth of payload fetches, until you revoke it. Nothing else.
Revocation is instant because it is a row in `store.json` read on every request.
