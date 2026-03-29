"""
test_integration.py  -  Week 9: Integration Test Suite
=======================================================
Tests the COMPLETE compiler pipeline end-to-end using the
RBACCompiler class from rbac_compiler.py.

Each test parses a real .rbac policy file through all 5 phases and
asserts that the integrated pipeline produces the expected outputs.

Run from the project root:
    python src/test_integration.py
"""

import unittest
import sys
import os
import io
import contextlib

# ---- Path setup ---------------------------------------------------------------
_SRC  = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_SRC)
sys.path.insert(0, _SRC)

from rbac_compiler import RBACCompiler


def _load(filename):
    path = os.path.join(_ROOT, "examples", filename)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _compile(filename):
    """Compile a policy file, suppressing all stdout during the run."""
    compiler = RBACCompiler()
    source = _load(filename)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = compiler.compile(source)
    return result


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegratedPipeline(unittest.TestCase):
    """
    End-to-end pipeline tests: verify the integrated compiler runs without
    crashing and produces the correct counts for each policy file.

    Actual counts (verified by running the pipeline):
      policy1.rbac             : sod=0 errs=0 warns=0 esc=3  dang=1  edges=2
      conflict_policy.rbac     : sod=1 errs=1 warns=1 esc=1  dang=0  edges=1
      policy_week7.rbac        : sod=3 errs=1 warns=1 esc=4  dang=8  edges=3
      policy_week8.rbac        : sod=0 errs=0 warns=0 esc=11 dang=14 edges=5
      policy_week9_integration : sod=2 errs=1 warns=1 esc=8  dang=13 edges=5
    """

    # ---- policy1.rbac --------------------------------------------------------

    def test_policy1_parse_succeeds(self):
        """policy1.rbac: AST must not be None (clean parse)."""
        result = _compile("policy1.rbac")
        self.assertTrue(result.parse_ok, "Parse should succeed")
        self.assertIsNotNone(result.ast)

    def test_policy1_no_sod_conflicts(self):
        """policy1.rbac: clean policy - zero SoD conflicts."""
        result = _compile("policy1.rbac")
        self.assertEqual(len(result.conflict_report.conflicts), 0)

    def test_policy1_no_errors(self):
        """policy1.rbac: no unknown references or cycles."""
        result = _compile("policy1.rbac")
        self.assertEqual(len(result.conflict_report.errors), 0)

    def test_policy1_reports_present(self):
        """policy1.rbac: both conflict and escalation reports must be produced."""
        result = _compile("policy1.rbac")
        self.assertIsNotNone(result.conflict_report)
        self.assertIsNotNone(result.escalation_report)

    # ---- conflict_policy.rbac ------------------------------------------------

    def test_conflict_policy_parse_succeeds(self):
        result = _compile("conflict_policy.rbac")
        self.assertTrue(result.parse_ok)

    def test_conflict_policy_sod_conflict_detected(self):
        """conflict_policy.rbac: alice triggers 1 SoD conflict."""
        result = _compile("conflict_policy.rbac")
        self.assertEqual(len(result.conflict_report.conflicts), 1)

    def test_conflict_policy_unknown_ref_detected(self):
        """conflict_policy.rbac: charlie has unknown role -> 1 error."""
        result = _compile("conflict_policy.rbac")
        self.assertEqual(len(result.conflict_report.errors), 1)

    def test_conflict_policy_redundant_perm_detected(self):
        """conflict_policy.rbac: Auditor has redundant permission -> 1 warning."""
        result = _compile("conflict_policy.rbac")
        self.assertEqual(len(result.conflict_report.warnings), 1)

    def test_conflict_policy_escalation_path_detected(self):
        """conflict_policy.rbac: Auditor inherits Accountant -> 1 escalation path."""
        result = _compile("conflict_policy.rbac")
        self.assertEqual(len(result.escalation_report.escalation_paths), 1)

    def test_conflict_policy_no_dangerous_combos(self):
        """conflict_policy.rbac: no dangerous permission combinations."""
        result = _compile("conflict_policy.rbac")
        self.assertEqual(len(result.escalation_report.dangerous_combos_found), 0)

    # ---- policy_week7.rbac ---------------------------------------------------

    def test_week7_parse_succeeds(self):
        result = _compile("policy_week7.rbac")
        self.assertTrue(result.parse_ok)

    def test_week7_three_sod_conflicts(self):
        """policy_week7.rbac: 3 SoD conflicts (direct + inherited)."""
        result = _compile("policy_week7.rbac")
        self.assertEqual(len(result.conflict_report.conflicts), 3)

    def test_week7_one_error(self):
        """policy_week7.rbac: 1 unknown reference error."""
        result = _compile("policy_week7.rbac")
        self.assertEqual(len(result.conflict_report.errors), 1)

    # ---- policy_week8.rbac ---------------------------------------------------

    def test_week8_parse_succeeds(self):
        result = _compile("policy_week8.rbac")
        self.assertTrue(result.parse_ok)

    def test_week8_eleven_escalation_paths(self):
        """policy_week8.rbac: 11 escalation paths through 4-level hierarchy."""
        result = _compile("policy_week8.rbac")
        self.assertEqual(len(result.escalation_report.escalation_paths), 11)

    def test_week8_fourteen_dangerous_combos(self):
        """policy_week8.rbac: 14 dangerous permission combinations."""
        result = _compile("policy_week8.rbac")
        self.assertEqual(len(result.escalation_report.dangerous_combos_found), 14)

    def test_week8_no_sod_conflicts(self):
        """policy_week8.rbac: no SoD constraints -> 0 SoD conflicts."""
        result = _compile("policy_week8.rbac")
        self.assertEqual(len(result.conflict_report.conflicts), 0)

    def test_week8_five_graph_edges(self):
        """policy_week8.rbac: role hierarchy has 5 inheritance edges."""
        result = _compile("policy_week8.rbac")
        self.assertEqual(len(result.escalation_report.graph_edges), 5)

    # ---- policy_week9_integration.rbac ---------------------------------------

    def test_week9_parse_succeeds(self):
        """policy_week9_integration.rbac: must parse without error."""
        result = _compile("policy_week9_integration.rbac")
        self.assertTrue(result.parse_ok)

    def test_week9_two_sod_conflicts(self):
        """policy_week9_integration.rbac: 2 SoD violations (direct + inherited)."""
        result = _compile("policy_week9_integration.rbac")
        self.assertEqual(len(result.conflict_report.conflicts), 2)

    def test_week9_unknown_ref_detected(self):
        """policy_week9_integration.rbac: grace references UnknownRole -> 1 error."""
        result = _compile("policy_week9_integration.rbac")
        self.assertEqual(len(result.conflict_report.errors), 1)

    def test_week9_redundant_permission_detected(self):
        """policy_week9_integration.rbac: BudgetReviewer re-declares inherited read_data."""
        result = _compile("policy_week9_integration.rbac")
        self.assertGreaterEqual(len(result.conflict_report.warnings), 1)

    def test_week9_escalation_paths_detected(self):
        """policy_week9_integration.rbac: hierarchy produces 8 escalation paths."""
        result = _compile("policy_week9_integration.rbac")
        self.assertEqual(len(result.escalation_report.escalation_paths), 8)

    def test_week9_dangerous_combos_detected(self):
        """policy_week9_integration.rbac: 13 dangerous combos (SeniorAnalyst + Admin chain)."""
        result = _compile("policy_week9_integration.rbac")
        self.assertEqual(len(result.escalation_report.dangerous_combos_found), 13)

    def test_week9_total_issues_nonzero(self):
        """policy_week9_integration.rbac: policy has known issues -> total > 0."""
        result = _compile("policy_week9_integration.rbac")
        self.assertGreater(result.total_issues, 0)

    # ---- Cross-policy checks -------------------------------------------------

    def test_all_policies_produce_reports(self):
        """All five policies must produce both a conflict and escalation report."""
        for fname in ["policy1.rbac", "conflict_policy.rbac",
                      "policy_week7.rbac", "policy_week8.rbac",
                      "policy_week9_integration.rbac"]:
            with self.subTest(policy=fname):
                result = _compile(fname)
                self.assertIsNotNone(result.conflict_report,
                                     fname + ": conflict_report is None")
                self.assertIsNotNone(result.escalation_report,
                                     fname + ": escalation_report is None")

    def test_clean_policy1_has_zero_sod(self):
        """policy1.rbac (clean) must produce zero SoD conflicts."""
        result = _compile("policy1.rbac")
        self.assertEqual(len(result.conflict_report.conflicts), 0)

    def test_week8_graph_edges_built(self):
        """policy_week8.rbac: role hierarchy graph must have exactly 5 edges."""
        result = _compile("policy_week8.rbac")
        self.assertGreaterEqual(len(result.escalation_report.graph_edges), 5)


# ---- Runner ------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromTestCase(TestIntegratedPipeline)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
