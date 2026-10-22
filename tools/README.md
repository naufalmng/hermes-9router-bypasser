# tools — authoring scripts (private)

The recipe generators are **not in this repository**.

They contain the literal anchors: the exact `find` / `with` byte strings for every
target. That is the payload. A public generator is a public patch.

They live at:

```
/opt/h9b-secrets/tools/build_hermes_payload.py
/opt/h9b-secrets/tools/build_router9_payload.py
/opt/h9b-secrets/tools/extract_anchors.py
```

## What each does

| script | purpose |
|---|---|
| `extract_anchors.py` | dumps the exact substring for a named construct out of a minified 9router chunk, so recipes are authored from real bytes instead of memory |
| `build_router9_payload.py` | diffs a pristine `npm pack` tarball against the installed patched tree and emits `find`/`with` pairs; also emits the `detect` marker for each recipe |
| `build_hermes_payload.py` | hand-verified anchors for the Python targets, with the signature fix that the earlier manual patch missed |

## Workflow when a new 9router version lands

```bash
cd /opt/h9b-secrets
mkdir -p /tmp/r9 && cd /tmp/r9 && npm pack 9router@<new> && tar xzf *.tgz
python3 /opt/h9b-secrets/tools/build_router9_payload.py \
  --pristine /tmp/r9/package/app/.next-cli-build/server/chunks \
  --patched  /usr/lib/node_modules/9router/app/.next-cli-build/server/chunks \
  --version  <new> \
  --out      /opt/h9b-secrets/payloads/router9-disarm.v1.json
h9bd payload check -dir /opt/h9b-secrets/payloads
kill -HUP $(pidof h9bd)
```

If a script reports `MISS <id>`, the construct moved. Read the new chunk, update
the anchor spec in the script, rerun. Never ship a recipe you have not seen
succeed against a real install.
