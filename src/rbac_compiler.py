"""
rbac_compiler.py  -  Week 9: Integrated RBAC Policy Compiler
=============================================================
Single entry-point that chains all compiler phases together:

  Phase 1 - Lexical Analysis     (lexer.py)
  Phase 2 - Syntax Analysis      (parser.py  ->  AST)
  Phase 3 - Semantic Analysis    (semantic_analyzer.py)
  Phase 4 - Conflict Detection   (conflict_detector.py  ->  ConflictReport)
  Phase 5 - Escalation Detection (escalation_detector.py  ->  EscalationReport)

Usage (from the project root):
    python src/rbac_compiler.py <policy_file.rbac>

Examples:
    python src/rbac_compiler.py examples/policy1.rbac
    python src/rbac_compiler.py examples/conflict_policy.rbac
    python src/rbac_compiler.py examples/policy_week7.rbac
    python src/rbac_compiler.py examples/policy_week8.rbac
    python src/rbac_compiler.py examples/policy_week9_integration.rbac
"""

from __future__ import annotations
import sys
import os

# Ensure src/ is on the module search path
_SRC = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SRC)

import ply.lex as _ply_lex
import lexer as _lexer_module
from parser               import parser as _yacc_parser
from semantic_analyzer    import SemanticAnalyzer
from conflict_detector    import ConflictDetector
from escalation_detector  import EscalationDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner(title: str, width: int = 68) -> str:
    return "\n  " + "=" * width + "\n  " + title + "\n  " + "=" * width


def _fresh_parse(source: str):
    """Parse *source* with a brand-new PLY lexer so repeated calls are safe."""
    lex = _ply_lex.lex(module=_lexer_module, errorlog=_ply_lex.NullLogger())
    return _yacc_parser.parse(source, lexer=lex)


# ---------------------------------------------------------------------------
# Compiler pipeline
# ---------------------------------------------------------------------------

class RBACCompiler:
    """
    Integrated RBAC Policy Compiler.

    Call compile(source) once per source text.  Returns a CompilerResult
    bundle containing every intermediate structure produced.
    """

    def compile(self, source: str) -> "CompilerResult":
        result = CompilerResult()

        # Phase 1 & 2: Lex + Parse
        print(_banner("PHASE 1 & 2 - LEXICAL + SYNTAX ANALYSIS"))
        ast = _fresh_parse(source)
        if ast is None:
            print("    [FAIL] Parsing FAILED - aborting compilation.")
            result.parse_ok = False
            return result

        result.parse_ok = True
        result.ast = ast
        print("    [OK] Parsed successfully - %d top-level statements found."
              % len(ast.statements))

        # Phase 3: Semantic analysis
        print(_banner("PHASE 3 - SEMANTIC ANALYSIS"))
        sa = SemanticAnalyzer()
        sa.visit(ast)
        sa_errors = sa.errors
        result.semantic_errors = sa_errors
        if sa_errors:
            for err in sa_errors:
                print("    [ERROR] " + err)
        else:
            print("    [OK] No semantic errors found.")

        # Phase 4: Conflict detection
        print(_banner("PHASE 4 - CONFLICT DETECTION  (SoD / Redundant / Unknown / Cycles)"))
        cd = ConflictDetector()
        c_report = cd.analyse(ast)
        result.conflict_report = c_report
        print(c_report.display())
        print("\n    Summary: %d error(s), %d SoD conflict(s), %d warning(s)  [%d issues total]"
              % (len(c_report.errors), len(c_report.conflicts), len(c_report.warnings),
                 len(c_report.errors) + len(c_report.conflicts) + len(c_report.warnings)))

        # Phase 5: Escalation detection
        print(_banner("PHASE 5 - PRIVILEGE ESCALATION DETECTION"))
        ed = EscalationDetector()
        e_report = ed.analyse(ast)
        result.escalation_report = e_report
        print(e_report.display())
        print("\n    Summary: %d escalation path(s), %d dangerous combo(s)  [%d issues total]"
              % (len(e_report.escalation_paths), len(e_report.dangerous_combos_found),
                 len(e_report.escalation_paths) + len(e_report.dangerous_combos_found)))

        # Final verdict
        print(_banner("COMPILER RESULT"))
        total = (len(c_report.errors) + len(c_report.conflicts) + len(c_report.warnings)
                 + len(e_report.escalation_paths) + len(e_report.dangerous_combos_found))
        if total == 0:
            print("    [OK] CLEAN POLICY - no security issues detected.")
        else:
            print("    [WARN] POLICY HAS %d ISSUE(S) - review the report above." % total)
        result.total_issues = total
        return result


# ---------------------------------------------------------------------------
# Result bundle
# ---------------------------------------------------------------------------

class CompilerResult:
    def __init__(self):
        self.parse_ok          = False
        self.ast               = None
        self.semantic_errors   = []
        self.conflict_report   = None
        self.escalation_report = None
        self.total_issues      = 0


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python src/rbac_compiler.py <policy_file.rbac>")
        sys.exit(1)

    policy_path = sys.argv[1]
    if not os.path.isfile(policy_path):
        print("Error: File not found - " + policy_path)
        sys.exit(1)

    with open(policy_path, "r", encoding="utf-8") as fh:
        source = fh.read()

    print("\n" + "=" * 70)
    print("  RBAC Policy DSL Compiler   -   Week 9: Integrated Pipeline")
    print("  Policy : " + policy_path)
    print("=" * 70)

    compiler = RBACCompiler()
    compiler.compile(source)

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    main()
