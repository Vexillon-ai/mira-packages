# mira-packages

The first-party **package index** for [MIRA](https://github.com/Vexillon-ai/MIRA).

A MIRA instance can discover and install packages (`.mirapkg` / `.miraskill`)
from configured *sources*. This repository is one such source: it serves a
signed catalog (`index.json`) listing available packages and, for each version,
where to download the artifact and the hashes/keys needed to trust it.

Discovery through a source never lowers MIRA's security bar — see
[Safety model](#safety-model).

## How a MIRA instance uses this repo

1. The operator adds this source and **pins its public key** in `mira_config.json`:
   ```jsonc
   // packages.sources[]
   {
     "name": "Vexillon",
     "index_url": "https://raw.githubusercontent.com/Vexillon-ai/mira-packages/main/index.json",
     "enabled": true,
     "pinned_key": "<base64 ed25519 public key>"
   }
   ```
   MIRA ships this entry **disabled with an empty key**; enabling it and pinning
   the key is a deliberate operator action.
2. On refresh, MIRA fetches `index.json`, then the detached signature
   `index.json.sig`, and verifies it against the pinned key before trusting any
   `download_url` in the catalog.
3. Packages then appear in MIRA's in-app **Browse** list. Installing an artifact
   runs MIRA's own per-artifact trust check (see below).

## Repository layout

```
index.json                 # the catalog (schema "1")
index.json.sig             # detached ed25519 signature over index.json's exact bytes
packages/
  <id>/<version>/<id>-<version>.mirapkg      # or .miraskill
.github/workflows/verify-packages.yml        # PR gate
.ci/validate_index.py                        # catalog integrity checker (run by CI)
```

The catalog and artifacts are served over `raw.githubusercontent.com`.

## `index.json` schema (`"1"`)

```jsonc
{
  "schema": "1",
  "generated_at": "<RFC3339 timestamp>",
  "packages": [
    {
      "id": "ai.vexillon.<name>",      // reverse-DNS; matches the artifact manifest id
      "name": "Human Name",
      "kind": "skill | mcp_server | cpp_provider | app",
      "latest": "1.2.0",               // must be the highest listed version
      "versions": [
        {
          "version": "1.2.0",
          "min_mira_version": "0.355.0",
          "download_url": "https://raw.githubusercontent.com/Vexillon-ai/mira-packages/main/packages/ai.vexillon.<name>/1.2.0/ai.vexillon.<name>-1.2.0.mirapkg",
          "sha256": "<64 hex chars of the artifact>",
          "size": 48213,              // exact byte size of the artifact
          "publisher": "Vexillon",
          "key_fingerprint": "fingerprint:<hex>",  // the artifact's own publisher key fingerprint
          "summary": "One-line description.",
          "homepage": "https://vexillon.ai/packages/<name>",
          "license": "AGPL-3.0"
        }
      ]
    }
  ]
}
```

Constraints the CI enforces: canonical `download_url` for each `id`+`version`,
the artifact file present with a matching `sha256` and `size`, artifacts within
MIRA's **10 MiB** download cap, `latest` equal to the highest version, and no
clobbering/downgrading a version already published on `main`.

## Submitting a package

1. Build and sign your artifact with the MIRA CLI, then package it:
   ```
   mira skill sign <skill-dir> --key <your-ed25519-key>
   mira skill package <skill-dir>          # produces the .miraskill / .mirapkg
   ```
2. Add it at `packages/<id>/<version>/<id>-<version>.<ext>`.
3. Add (or extend) the package's entry in `index.json`:
   - `sha256` = `sha256sum` of the artifact
   - `size` = its exact byte size
   - `key_fingerprint` = the artifact's own publisher-key fingerprint
4. Open a pull request. CI (`verify-packages.yml`) validates catalog integrity
   and surfaces manifest problems. A maintainer reviews and merges.

After merge, a maintainer re-signs and republishes the catalog:
```
mira skill index-sign index.json --key <maintainer-key>   # writes index.json.sig
git add index.json index.json.sig && git commit && git push
```

**Trust:** artifacts signed with the first-party Vexillon key show as
**Verified** in MIRA. Community submissions are signed with the author's own key
and are **Untrusted** (trust-on-first-use) until an operator pins that key.

## Safety model

The index only aids **discovery**. A tampered or unsigned catalog can **never**
cause an unsigned or untrusted artifact to install silently, because the
authoritative trust decision is made **per artifact at install time** — the
client re-checks the artifact's `sha256`, its embedded signature, and the
operator's trust store. The catalog signature exists for one narrower purpose:
so a catalog cannot redirect a *trusted package id* to a malicious
`download_url`.

## For maintainers: the signing key

The Vexillon signing key is minted **once** by the project owner and is **never
committed** to this repo (`*.ed25519` and similar are git-ignored):

```
mira skill keygen --out vexillon.ed25519    # mode 0600; back it up offline
```

`keygen` prints the public key (base64) and fingerprint. The public key is what
operators pin as `pinned_key`; the same key signs first-party artifacts and the
catalog.

## License

Package artifacts declare their own license in the catalog. MIRA itself is
AGPL-3.0-or-later.
