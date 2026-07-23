#!/usr/bin/env python3
"""Enforce the firmware Rust coverage ratchet.

Compares per-package line coverage measured by ``cargo llvm-cov`` against the
floors checked into ``ci/ratchet.json``. Floors only tighten (EXECUTION-ETHICS.md
Section D): the gate fails if any package's measured coverage drops below its
floor. It also fails loud on drift -- every workspace package must have a floor,
and every floor must map to a real workspace package -- so a phase that adds a
crate cannot silently skip recording its baseline.

Usage:
    check_coverage_ratchet.py <cargo-llvm-cov-json> <ratchet-json>

The coverage JSON is produced by:
    cargo llvm-cov --workspace --all-features --summary-only \\
        --json --output-path <path>
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Floating-point slack so an exact-match floor (e.g. 100.0) is never tripped by
# representation noise.
EPSILON = 1e-6


def workspace_packages() -> dict[str, Path]:
    """Return {package name: package root dir} for workspace members only."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    meta = json.loads(out)
    return {
        pkg["name"]: Path(pkg["manifest_path"]).resolve().parent
        for pkg in meta["packages"]
    }


def measured_line_coverage(cov_json: Path, roots: dict[str, Path]) -> dict[str, float]:
    """Aggregate line coverage per package from the llvm-cov export JSON.

    Each covered file is attributed to the workspace package whose root dir is
    the longest matching prefix of the file path. A package with no measured
    lines is treated as fully covered (nothing to miss).
    """
    data = json.loads(cov_json.read_text())
    covered: dict[str, int] = {name: 0 for name in roots}
    total: dict[str, int] = {name: 0 for name in roots}

    for file_entry in data["data"][0]["files"]:
        path = Path(file_entry["filename"]).resolve()
        owner, owner_len = None, -1
        for name, root in roots.items():
            root_str = str(root)
            if str(path).startswith(root_str) and len(root_str) > owner_len:
                owner, owner_len = name, len(root_str)
        if owner is None:
            continue
        lines = file_entry["summary"]["lines"]
        covered[owner] += lines["covered"]
        total[owner] += lines["count"]

    return {
        name: (100.0 if total[name] == 0 else 100.0 * covered[name] / total[name])
        for name in roots
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <cargo-llvm-cov-json> <ratchet-json>", file=sys.stderr)
        return 2

    cov_json = Path(argv[1])
    ratchet = json.loads(Path(argv[2]).read_text())
    floors: dict[str, float] = ratchet["coverage"]["floors"]

    roots = workspace_packages()
    missing_floor = sorted(set(roots) - set(floors))
    stale_floor = sorted(set(floors) - set(roots))
    if missing_floor:
        print(
            "coverage-ratchet FAIL: workspace packages without a floor in "
            f"ci/ratchet.json: {missing_floor} (record their measured baseline)",
            file=sys.stderr,
        )
        return 1
    if stale_floor:
        print(
            "coverage-ratchet FAIL: ci/ratchet.json floors for non-existent "
            f"packages: {stale_floor} (remove the stale entries)",
            file=sys.stderr,
        )
        return 1

    measured = measured_line_coverage(cov_json, roots)
    failed = False
    print("package                        measured   floor   status")
    print("-" * 58)
    for name in sorted(roots):
        got, floor = measured[name], float(floors[name])
        ok = got + EPSILON >= floor
        failed = failed or not ok
        print(f"{name:<30} {got:7.2f}%  {floor:6.2f}%  {'ok' if ok else 'BELOW FLOOR'}")

    if failed:
        print("\ncoverage-ratchet FAIL: coverage dropped below a checked-in floor.",
              file=sys.stderr)
        return 1
    print("\ncoverage-ratchet ok: all packages meet their floor.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
