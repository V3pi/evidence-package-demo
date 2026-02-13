#!/usr/bin/env python3
"""
v3pi_verify.py — V3pi Evidence Package Verifier
=================================================
Version: 1.0.0

Offline, read-only utility that validates the integrity and completeness
of a delivered V3pi evidence package by verifying a complete hash inventory.

This tool:
  - Reads inventory.json from the package directory
  - Computes SHA-256 for every listed file
  - Confirms all listed files are present
  - Confirms no unexpected files exist (unless allowlisted)
  - Emits a clear PASS/FAIL result

This tool does NOT:
  - Modify any files
  - Access the network
  - Recompute structural identities
  - Require installation or admin privileges

Source: https://github.com/V3pi/evidence-package-demo

Exit codes:
    0: PASS
    1: FAIL (mismatch, missing, or extra files)
    2: ERROR (invalid inventory, unreadable files, bad arguments)
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

__version__ = "1.0.0"


# =============================================================================
# Constants
# =============================================================================

DEFAULT_INVENTORY = "inventory.json"
DEFAULT_ALLOWLIST = {".DS_Store", "Thumbs.db", "desktop.ini"}
SCHEMA_VERSION = "1.0.0"


# =============================================================================
# Hash computation
# =============================================================================

def compute_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


# =============================================================================
# Inventory loading and validation
# =============================================================================

def load_inventory(inventory_path: Path) -> Dict[str, Any]:
    """
    Load and validate inventory.json structure.
    Returns the parsed inventory dict.
    Exits with code 2 on any structural problem.
    """
    if not inventory_path.exists():
        print(f"ERROR: Inventory file not found: {inventory_path}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(inventory_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"ERROR: Invalid inventory file: {e}", file=sys.stderr)
        sys.exit(2)

    # Schema checks
    if not isinstance(data, dict):
        print("ERROR: Inventory must be a JSON object.", file=sys.stderr)
        sys.exit(2)

    for required_key in ("schema_version", "package", "files", "hashes"):
        if required_key not in data:
            print(f"ERROR: Inventory missing required key: '{required_key}'",
                  file=sys.stderr)
            sys.exit(2)

    if not isinstance(data["files"], list):
        print("ERROR: Inventory 'files' must be an array.", file=sys.stderr)
        sys.exit(2)

    for i, entry in enumerate(data["files"]):
        for field in ("path", "sha256"):
            if field not in entry:
                print(f"ERROR: File entry {i} missing '{field}'.",
                      file=sys.stderr)
                sys.exit(2)
        # Security: reject absolute paths and path traversal
        fpath = entry["path"]
        if os.path.isabs(fpath) or ".." in fpath.split("/"):
            print(f"ERROR: Invalid path in inventory: '{fpath}'",
                  file=sys.stderr)
            sys.exit(2)

    return data


# =============================================================================
# Verification engine
# =============================================================================

def verify_package(
    package_dir: Path,
    inventory: Dict[str, Any],
    strict_extras: bool = True,
    allow_extra: Optional[Set[str]] = None,
    inventory_filename: str = DEFAULT_INVENTORY,
) -> Dict[str, Any]:
    """
    Run all verification checks against the package.
    Returns a verification report dict.
    """
    if allow_extra is None:
        allow_extra = DEFAULT_ALLOWLIST.copy()

    # The inventory file itself and any signature files are always allowed
    allow_extra.add(inventory_filename)
    allow_extra.add("inventory.sig")
    # The verifier binary itself may be in the directory
    allow_extra.update({
        "v3pi-verify-windows-x64.exe",
        "v3pi-verify-macos-x64",
        "v3pi-verify-macos-arm64",
        "v3pi-verify-linux-x64",
        "v3pi_verify.py",
        "v3pi-verify.pyz",
    })

    file_entries = inventory["files"]

    # Collect expected paths (normalized to /)
    expected_paths: Set[str] = set()
    for entry in file_entries:
        expected_paths.add(entry["path"])

    # Enumerate actual files on disk
    actual_files: Set[str] = set()
    for root, _dirs, filenames in os.walk(package_dir):
        for fname in filenames:
            full = Path(root) / fname
            rel = full.relative_to(package_dir).as_posix()
            actual_files.add(rel)

    # --- Completeness checks ---
    missing_files = []
    for entry in file_entries:
        fpath = entry["path"]
        full_path = package_dir / fpath
        if not full_path.exists():
            missing_files.append(fpath)

    extra_files = []
    if strict_extras:
        for rel in sorted(actual_files - expected_paths):
            fname = rel.split("/")[-1]
            if fname not in allow_extra and rel not in allow_extra:
                extra_files.append(rel)

    # --- Integrity checks ---
    hash_matches = 0
    hash_mismatches = []
    size_mismatches = []
    hash_checked = 0

    for entry in file_entries:
        fpath = entry["path"]
        expected_hash = entry["sha256"]
        full_path = package_dir / fpath

        if not full_path.exists():
            continue  # Already counted as missing

        # Size check (fast fail before expensive hash)
        expected_size = entry.get("size_bytes")
        if expected_size is not None:
            actual_size = full_path.stat().st_size
            if actual_size != expected_size:
                size_mismatches.append({
                    "path": fpath,
                    "expected_bytes": expected_size,
                    "actual_bytes": actual_size,
                })

        hash_checked += 1
        actual_hash = compute_sha256(full_path)

        if actual_hash == expected_hash:
            hash_matches += 1
        else:
            hash_mismatches.append({
                "path": fpath,
                "expected": expected_hash,
                "actual": actual_hash,
            })

    # --- Inventory self-hash check ---
    # The generator computes inventory_sha256 over canonical JSON bytes
    # BEFORE embedding the hash. To verify: reconstruct that pre-hash
    # state, canonicalize with identical settings, and compare.
    inventory_hash_status = "SKIPPED"
    inventory_hash_ok = True
    declared_hash = inventory.get("hashes", {}).get("inventory_sha256")
    if declared_hash:
        # Reconstruct pre-hash inventory
        verify_copy = json.loads(json.dumps(inventory))
        verify_copy["hashes"] = {}
        canonical = json.dumps(
            verify_copy, indent=2, sort_keys=True, ensure_ascii=False
        )
        recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if recomputed == declared_hash:
            inventory_hash_status = "VERIFIED"
        else:
            inventory_hash_status = "MISMATCH"
            inventory_hash_ok = False

    # --- Result ---
    passed = (
        len(missing_files) == 0
        and len(extra_files) == 0
        and len(hash_mismatches) == 0
        and len(size_mismatches) == 0
        and hash_checked == len(file_entries)
        and inventory_hash_ok
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "verifier_version": __version__,
        "verified_at_utc": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "package_path": str(package_dir),
        "inventory_path": inventory_filename,
        "signature_status": "SKIPPED",
        "inventory_hash_status": inventory_hash_status,
        "counts": {
            "files_listed": len(file_entries),
            "files_present": hash_checked,
            "hash_matches": hash_matches,
            "hash_mismatches": len(hash_mismatches),
            "size_mismatches": len(size_mismatches),
            "missing_files": len(missing_files),
            "extra_files": len(extra_files),
        },
        "missing_files": missing_files,
        "extra_files": extra_files,
        "hash_mismatches": hash_mismatches,
        "size_mismatches": size_mismatches,
        "result": "PASS" if passed else "FAIL",
    }


# =============================================================================
# Output formatting
# =============================================================================

def print_report(report: Dict[str, Any]) -> None:
    """Print human-readable verification summary."""
    counts = report["counts"]

    print()
    print("=" * 50)
    print("  V3pi Evidence Package Verification")
    print("=" * 50)
    print()
    print(f"  Files listed:      {counts['files_listed']}")
    print(f"  Files present:     {counts['files_present']}")
    print(f"  Hash matches:      {counts['hash_matches']}/{counts['files_listed']}")
    print(f"  Size mismatches:   {counts['size_mismatches']}")
    print(f"  Missing files:     {counts['missing_files']}")
    print(f"  Extra files:       {counts['extra_files']}")
    print(f"  Inventory hash:    {report['inventory_hash_status']}")
    print(f"  Signature:         {report['signature_status']}")
    print()

    if report["missing_files"]:
        print("  MISSING FILES:")
        for f in report["missing_files"]:
            print(f"    - {f}")
        print()

    if report["extra_files"]:
        print("  UNEXPECTED FILES:")
        for f in report["extra_files"]:
            print(f"    - {f}")
        print()

    if report["size_mismatches"]:
        print("  SIZE MISMATCHES:")
        for m in report["size_mismatches"]:
            print(f"    - {m['path']}")
            print(f"      expected: {m['expected_bytes']} bytes")
            print(f"      actual:   {m['actual_bytes']} bytes")
        print()

    if report["hash_mismatches"]:
        print("  HASH MISMATCHES:")
        for m in report["hash_mismatches"]:
            print(f"    - {m['path']}")
            print(f"      expected: {m['expected']}")
            print(f"      actual:   {m['actual']}")
        print()

    if report["inventory_hash_status"] == "MISMATCH":
        print("  INVENTORY INTEGRITY:")
        print("    inventory.json self-hash does not match.")
        print("    The inventory file may have been altered.")
        print()

    result = report["result"]
    if result == "PASS":
        print(f"  Result:            PASS")
        print()
        print("  All files verified. Package integrity confirmed.")
    else:
        print(f"  Result:            FAIL")
        print()
        print("  Package integrity check FAILED.")
        print("  One or more files are missing, altered, or unexpected.")

    print()
    print("=" * 50)
    print()


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="V3pi Evidence Package Verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  v3pi_verify.py --path ./deliverables\n"
            "  v3pi_verify.py --path ./deliverables --out verify_report.json\n"
            "  v3pi_verify.py --path ./deliverables --no-strict-extras\n"
        ),
    )
    parser.add_argument(
        "--path", type=Path, required=True,
        help="Path to the evidence package directory",
    )
    parser.add_argument(
        "--inventory", type=str, default=DEFAULT_INVENTORY,
        help=f"Inventory filename (default: {DEFAULT_INVENTORY})",
    )
    parser.add_argument(
        "--out", type=str, default=None,
        help="Write machine-readable verification report to this path",
    )
    parser.add_argument(
        "--no-strict-extras", action="store_true",
        help="Allow extra files without failing",
    )
    parser.add_argument(
        "--allow-extra", type=str, nargs="*", default=None,
        help="Additional filenames to allowlist",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress human-readable output (use with --out)",
    )

    args = parser.parse_args()

    # Validate package path
    if not args.path.is_dir():
        print(f"ERROR: Package path is not a directory: {args.path}",
              file=sys.stderr)
        return 2

    # Load inventory
    inventory_path = args.path / args.inventory
    inventory = load_inventory(inventory_path)

    # Build allowlist
    allow_extra = DEFAULT_ALLOWLIST.copy()
    if args.allow_extra:
        allow_extra.update(args.allow_extra)

    # Run verification
    report = verify_package(
        package_dir=args.path,
        inventory=inventory,
        strict_extras=not args.no_strict_extras,
        allow_extra=allow_extra,
        inventory_filename=args.inventory,
    )

    # Output
    if not args.quiet:
        print_report(report)

    if args.out:
        out_path = Path(args.out)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        if not args.quiet:
            print(f"  Report written to: {out_path}")
            print()

    # Exit code: 0=PASS, 1=FAIL
    if report["result"] == "PASS":
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
