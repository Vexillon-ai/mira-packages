#!/usr/bin/env python3
"""Integrity gate for the mira-packages catalog.

No cryptography here on purpose: a MIRA instance's *authoritative* trust decision
is made per-artifact at install time (sha256 + the artifact's own signature +
the operator's trust store). This script only checks that the catalog is
internally consistent and that a pull request cannot clobber or downgrade a
version that is already published on `main`.

What it checks:
  - index.json parses and is schema "1" with a generated_at timestamp
  - each package: reverse-DNS id (unique), known kind, non-empty versions
  - each version: all required fields, well-formed version / min_mira_version,
    64-hex sha256, 'fingerprint:<hex>' key_fingerprint, positive integer size
  - the download_url is the canonical raw.githubusercontent.com path for that
    id+version, the artifact file exists in the repo, and its real sha256 + byte
    size match the entry (and are within the client's download cap)
  - `latest` is present among versions and is the highest version
  - vs the published catalog on main: no version is clobbered (sha256 change) and
    `latest` is never downgraded (removals are reported as a warning)

Usage (from the repo root):  python3 .ci/validate_index.py
Exit 0 = OK, 1 = one or more hard errors.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.json"

# Must not exceed the MIRA client's install-from-URL download cap (10 MiB);
# a larger artifact would pass CI but fail to fetch on install.
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024

KINDS = {"skill", "mcp_server", "cpp_provider", "app"}
ARTIFACT_EXTS = (".mirapkg", ".miraskill")
RAW_PREFIX = "https://raw.githubusercontent.com/Vexillon-ai/mira-packages/main/"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FP_RE = re.compile(r"^fingerprint:[0-9a-f]{16,}$")
ID_RE = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9][a-z0-9-]*)+$")  # reverse-DNS, e.g. ai.vexillon.foo
VER_RE = re.compile(r"^\d+\.\d+\.\d+$")

errors: list[str] = []
warnings: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def semver(v: str) -> tuple[int, int, int]:
    a, b, c = v.split(".")
    return (int(a), int(b), int(c))


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def published_index() -> dict | None:
    """index.json as published on origin/main (for monotonicity). None if absent."""
    for ref in ("origin/main", "main"):
        out = subprocess.run(
            ["git", "show", f"{ref}:index.json"],
            cwd=ROOT, capture_output=True,
        )
        if out.returncode == 0:
            try:
                return json.loads(out.stdout.decode("utf-8"))
            except json.JSONDecodeError:
                return None
    return None


def check_version(pid: str, ver: dict) -> None:
    v = ver.get("version", "")
    where = f"{pid} {v or '?'}"
    required = ("version", "min_mira_version", "download_url", "sha256",
               "size", "publisher", "key_fingerprint", "summary", "license")
    for field in required:
        if field not in ver:
            err(f"{where}: missing field '{field}'")
    if not VER_RE.match(v):
        err(f"{where}: version must be X.Y.Z")
    if not VER_RE.match(str(ver.get("min_mira_version", ""))):
        err(f"{where}: min_mira_version must be X.Y.Z")
    if not SHA256_RE.match(str(ver.get("sha256", ""))):
        err(f"{where}: sha256 must be 64 lowercase hex chars")
    if not FP_RE.match(str(ver.get("key_fingerprint", ""))):
        err(f"{where}: key_fingerprint must look like 'fingerprint:<hex>'")
    size = ver.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        err(f"{where}: size must be a positive integer")

    url = ver.get("download_url", "")
    expected_stem = f"{pid}-{v}"
    if not url.startswith(RAW_PREFIX):
        err(f"{where}: download_url must start with {RAW_PREFIX}")
        return
    rel = url[len(RAW_PREFIX):]
    exp_dir = f"packages/{pid}/{v}/"
    if not rel.startswith(exp_dir):
        err(f"{where}: download_url path must be under {exp_dir}")
        return
    fname = rel[len(exp_dir):]
    if "/" in fname or not fname.startswith(expected_stem) or not fname.endswith(ARTIFACT_EXTS):
        err(f"{where}: artifact must be named {expected_stem}.mirapkg or {expected_stem}.miraskill")
        return
    fpath = ROOT / rel
    if not fpath.is_file():
        err(f"{where}: artifact file missing from the repo: {rel}")
        return
    actual_sha = sha256_file(fpath)
    actual_size = fpath.stat().st_size
    if isinstance(size, int) and actual_size != size:
        err(f"{where}: size mismatch (index {size} vs file {actual_size})")
    if ver.get("sha256") != actual_sha:
        err(f"{where}: sha256 mismatch (index {str(ver.get('sha256'))[:12]}... vs file {actual_sha[:12]}...)")
    if actual_size > MAX_ARTIFACT_BYTES:
        err(f"{where}: artifact is {actual_size} bytes, over the {MAX_ARTIFACT_BYTES}-byte cap")


def main() -> int:
    try:
        idx = json.loads(INDEX.read_text(encoding="utf-8"))
    except FileNotFoundError:
        err("index.json not found at repo root")
        idx = None
    except json.JSONDecodeError as e:
        err(f"index.json is not valid JSON: {e}")
        idx = None

    if idx is not None:
        if idx.get("schema") != "1":
            err(f'schema must be "1", got {idx.get("schema")!r}')
        if not isinstance(idx.get("generated_at"), str) or not idx.get("generated_at"):
            err("generated_at must be a non-empty RFC3339 string")
        packages = idx.get("packages")
        if not isinstance(packages, list):
            err("packages must be a list")
            packages = []

        seen_ids: set[str] = set()
        for pk in packages:
            pid = pk.get("id", "")
            if not ID_RE.match(pid):
                err(f"bad package id {pid!r} (want reverse-DNS, e.g. ai.vexillon.name)")
            if pid in seen_ids:
                err(f"duplicate package id {pid!r}")
            seen_ids.add(pid)
            if pk.get("kind") not in KINDS:
                err(f"{pid}: kind must be one of {sorted(KINDS)}")
            for field in ("name", "latest", "versions"):
                if field not in pk:
                    err(f"{pid}: missing field '{field}'")
            versions = pk.get("versions")
            if not isinstance(versions, list) or not versions:
                err(f"{pid}: versions must be a non-empty list")
                continue
            vset: set[str] = set()
            for ver in versions:
                v = ver.get("version", "")
                if v in vset:
                    err(f"{pid}: duplicate version {v}")
                vset.add(v)
                check_version(pid, ver)
            latest = pk.get("latest")
            valid_vers = {v for v in vset if VER_RE.match(v)}
            if latest not in vset:
                err(f"{pid}: latest {latest!r} is not among the listed versions")
            elif valid_vers:
                highest = max(valid_vers, key=semver)
                if latest != highest:
                    err(f"{pid}: latest is {latest} but the highest version is {highest}")

        # Monotonicity vs the catalog already published on main.
        base = published_index()
        if base and isinstance(idx, dict):
            base_sha: dict[tuple[str, str], str] = {}
            base_latest: dict[str, str] = {}
            for pk in base.get("packages", []):
                base_latest[pk.get("id")] = pk.get("latest", "")
                for ver in pk.get("versions", []):
                    base_sha[(pk.get("id"), ver.get("version"))] = ver.get("sha256")
            cur_sha: dict[tuple[str, str], str] = {}
            for pk in packages:
                for ver in pk.get("versions", []):
                    cur_sha[(pk.get("id"), ver.get("version"))] = ver.get("sha256")
            for key, sha in base_sha.items():
                if key in cur_sha and cur_sha[key] != sha:
                    err(f"{key[0]} {key[1]}: cannot change (clobber) an already-published version")
                elif key not in cur_sha:
                    warn(f"{key[0]} {key[1]}: an already-published version was removed")
            cur_latest = {pk.get("id"): pk.get("latest", "") for pk in packages}
            for pid, bl in base_latest.items():
                cl = cur_latest.get(pid, "")
                if VER_RE.match(bl or "") and VER_RE.match(cl or "") and semver(cl) < semver(bl):
                    err(f"{pid}: latest downgraded {bl} -> {cl}")

    for w in warnings:
        print(f"  ! {w}")
    if errors:
        print(f"FAIL validate_index: {len(errors)} problem(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    n = len(idx.get("packages", [])) if isinstance(idx, dict) else 0
    print(f"OK validate_index: {n} package(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
