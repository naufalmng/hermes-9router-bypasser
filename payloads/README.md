# payloads — server-side only

**The recipes in this directory are NOT published in the public repository.**

That is the whole security model. The public repo ships the engine; the recipes
live on the licence server (or in a private repo) and are delivered sealed, per
request, bound to a licence and a machine.

If the recipes were committed publicly, anyone could skip the CDK entirely — they
would just read the anchors and patch by hand. The obfuscated client would be
decoration.

## Where the real files live

```
/opt/h9b-secrets/payloads/          server-side, 0700, not in any public repo
/var/lib/h9b/payloads/              alternative location for production
```

`h9bd serve -payloads <dir>` points at whichever you use. `kill -HUP` reloads
without downtime.

## What IS committed

`example.recipe.json` — the schema, with placeholder anchors. Enough for a
contributor to understand the format and run `h9bd payload check`, useless to
someone trying to reproduce a patch.

## Regenerating

```bash
# 9router: diff a pristine tarball against the installed, patched tree
make payload R9VER=0.5.95

# Hermes: hand-verified anchors in tools/build_hermes_payload.py
python3 tools/build_hermes_payload.py --out /opt/h9b-secrets/payloads/hermes-guardrail.v1.json

h9bd payload check -dir /opt/h9b-secrets/payloads
```

Never `git add payloads/*.json` — `.gitignore` blocks it, but check `git status`
before every push anyway.
