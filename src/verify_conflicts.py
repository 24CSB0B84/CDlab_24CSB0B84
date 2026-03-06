"""
verify_conflicts.py  –  Week 7: Main Conflict Verification Tool
==============================================================
Usage:
    python src/verify_conflicts.py <policy_file>

Displays:
  1. The Policy file content
  2. The Symbol Table (roles / permissions / users)
  3. The Conflict Report (errors, SoD violations, warnings)
"""

import sys
import os

# Ensure src/ is on the path when run from project root
sys.path.insert(0, os.path.dirname(__file__))

from parser import parser
from conflict_detector import ConflictDetector


DIVIDER = "=" * 60


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/verify_conflicts.py <policy_file>")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        with open(filename, "r") as fh:
            source = fh.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

    # ── 1. Show source ──────────────────────────────────────────────
    print(f"\n{DIVIDER}")
    print(f"  POLICY FILE: {filename}")
    print(DIVIDER)
    for i, line in enumerate(source.splitlines(), 1):
        print(f"  {i:3}: {line}")

    # ── 2. Parse ────────────────────────────────────────────────────
    policy = parser.parse(source)
    if not policy:
        print("\n[ERROR] Parsing failed. Cannot continue.")
        sys.exit(1)

    # ── 3. Build symbol table + detect conflicts ────────────────────
    detector = ConflictDetector()
    report   = detector.analyse(policy)
    st       = detector.symbol_table

    # ── 4. Print symbol table ───────────────────────────────────────
    print("\n" + st.display())

    # ── 5. Print conflict report ────────────────────────────────────
    print(f"\n{DIVIDER}")
    print("  CONFLICT DETECTION REPORT")
    print(DIVIDER)
    print(report.display())
    print(DIVIDER)

    total = len(report.errors) + len(report.conflicts) + len(report.warnings)
    print(f"\n  Summary: {len(report.errors)} error(s), "
          f"{len(report.conflicts)} SoD conflict(s), "
          f"{len(report.warnings)} warning(s)  [{total} issues total]")
    print()


if __name__ == "__main__":
    main()
