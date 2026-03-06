
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from parser import parser
from escalation_detector import EscalationDetector

DIVIDER = "=" * 60


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/verify_escalation.py <policy_file>")
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

    # ── 3. Analyse ───────────────────────────────────────────────────
    detector = EscalationDetector()
    report   = detector.analyse(policy)
    st       = detector.symbol_table

    # ── 4. Symbol table ─────────────────────────────────────────────
    print("\n" + st.display())

    # ── 5. Escalation report ────────────────────────────────────────
    print(f"\n{DIVIDER}")
    print("  PRIVILEGE ESCALATION REPORT")
    print(DIVIDER)
    print(report.display())
    print(DIVIDER)

    n_paths  = len(report.escalation_paths)
    n_combos = len(report.dangerous_combos_found)
    n_warn   = len(report.warnings)
    print(f"\n  Summary: {n_paths} escalation path(s), "
          f"{n_combos} dangerous combo(s), "
          f"{n_warn} warning(s)  [{n_paths + n_combos} issues total]")
    print()


if __name__ == "__main__":
    main()
