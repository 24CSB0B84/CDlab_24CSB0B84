"""
test_conflict_detector.py  –  Week 7: Unit Tests for Conflict Detection
=======================================================================
Run: python -m pytest src/test_conflict_detector.py -v
  or: python src/test_conflict_detector.py
"""

import unittest
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import ast_nodes as ast
from conflict_detector import ConflictDetector


class TestSymbolTablePopulation(unittest.TestCase):
    """Verify that the symbol table is built correctly from the AST."""

    def _run(self, statements):
        d = ConflictDetector()
        policy = ast.Policy(statements=statements)
        report = d.analyse(policy)
        return d, report

    def test_roles_registered(self):
        d, _ = self._run([
            ast.Role(name="Admin"),
            ast.Role(name="Viewer"),
        ])
        self.assertIn("Admin", d.symbol_table.roles)
        self.assertIn("Viewer", d.symbol_table.roles)

    def test_permissions_registered(self):
        d, _ = self._run([
            ast.Permission(name="read_data"),
            ast.Permission(name="write_data"),
        ])
        self.assertIn("read_data", d.symbol_table.permissions)
        self.assertIn("write_data", d.symbol_table.permissions)

    def test_users_registered(self):
        d, _ = self._run([
            ast.Role(name="Admin"),
            ast.User(name="alice", roles=["Admin"]),
        ])
        self.assertIn("alice", d.symbol_table.users)

    def test_duplicate_role_raises_error(self):
        _, report = self._run([
            ast.Role(name="Admin"),
            ast.Role(name="Admin"),
        ])
        self.assertTrue(any("Duplicate role" in e for e in report.errors))

    def test_duplicate_user_raises_error(self):
        _, report = self._run([
            ast.Role(name="Admin"),
            ast.User(name="alice", roles=["Admin"]),
            ast.User(name="alice", roles=["Admin"]),
        ])
        self.assertTrue(any("Duplicate user" in e for e in report.errors))


class TestUnknownReferences(unittest.TestCase):

    def test_unknown_role_in_user_assignment(self):
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.User(name="alice", roles=["ghost_role"])
        ])
        report = d.analyse(policy)
        self.assertTrue(any("ghost_role" in e for e in report.errors))

    def test_unknown_parent_role(self):
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="Child", parents=["NonExistentParent"])
        ])
        report = d.analyse(policy)
        self.assertTrue(any("NonExistentParent" in e for e in report.errors))

    def test_known_references_no_error(self):
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="Admin"),
            ast.User(name="alice", roles=["Admin"]),
        ])
        report = d.analyse(policy)
        self.assertEqual(report.errors, [])


class TestSoDConflicts(unittest.TestCase):

    def test_direct_sod_conflict(self):
        """User directly holds both conflicting roles."""
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="Accountant"),
            ast.Role(name="Trader"),
            ast.Conflict(role1="Accountant", role2="Trader"),
            ast.User(name="alice", roles=["Accountant", "Trader"]),
        ])
        report = d.analyse(policy)
        self.assertTrue(any("alice" in c and "Accountant" in c and "Trader" in c
                            for c in report.conflicts))

    def test_inherited_sod_conflict(self):
        """User holds child role that inherits one of the conflicting roles."""
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="Accountant"),
            ast.Role(name="SeniorAccountant", parents=["Accountant"]),
            ast.Role(name="Trader"),
            ast.Conflict(role1="Accountant", role2="Trader"),
            ast.User(name="dave", roles=["SeniorAccountant", "Trader"]),
        ])
        report = d.analyse(policy)
        self.assertTrue(any("dave" in c for c in report.conflicts))

    def test_no_sod_conflict_for_clean_user(self):
        """User with a single non-conflicting role should be clean."""
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="Accountant"),
            ast.Role(name="Trader"),
            ast.Conflict(role1="Accountant", role2="Trader"),
            ast.User(name="bob", roles=["Accountant"]),
        ])
        report = d.analyse(policy)
        self.assertEqual(report.conflicts, [])

    def test_conflict_not_triggered_without_constraint(self):
        """Roles that are NOT declared in a conflict statement should be fine."""
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="A"),
            ast.Role(name="B"),
            ast.User(name="u", roles=["A", "B"]),
        ])
        report = d.analyse(policy)
        self.assertEqual(report.conflicts, [])


class TestRedundantPermissions(unittest.TestCase):

    def test_redundant_permission_detected(self):
        """Child role explicitly lists a permission it already inherits."""
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="Accountant", permissions=["read_financials"]),
            ast.Role(name="Auditor", parents=["Accountant"],
                     permissions=["read_financials", "audit_log"]),
        ])
        report = d.analyse(policy)
        self.assertTrue(any("Auditor" in w and "read_financials" in w
                            for w in report.warnings))

    def test_no_redundancy_when_permission_unique(self):
        """No warning if child adds a genuinely new permission."""
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="Accountant", permissions=["read_financials"]),
            ast.Role(name="Auditor", parents=["Accountant"],
                     permissions=["audit_log"]),
        ])
        report = d.analyse(policy)
        self.assertEqual(report.warnings, [])

    def test_deep_hierarchy_redundancy(self):
        """Permission inherited two levels deep should still be flagged."""
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="Base", permissions=["p1"]),
            ast.Role(name="Mid", parents=["Base"]),
            ast.Role(name="Top", parents=["Mid"], permissions=["p1"]),
        ])
        report = d.analyse(policy)
        self.assertTrue(any("Top" in w and "p1" in w for w in report.warnings))


class TestCyclicInheritance(unittest.TestCase):

    def test_direct_cycle(self):
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="A", parents=["B"]),
            ast.Role(name="B", parents=["A"]),
        ])
        report = d.analyse(policy)
        self.assertTrue(any("Cyclic" in e for e in report.errors))

    def test_no_cycle_in_linear_hierarchy(self):
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Role(name="Base"),
            ast.Role(name="Mid", parents=["Base"]),
            ast.Role(name="Top", parents=["Mid"]),
        ])
        report = d.analyse(policy)
        cycle_errors = [e for e in report.errors if "Cyclic" in e]
        self.assertEqual(cycle_errors, [])


class TestCleanPolicy(unittest.TestCase):

    def test_fully_clean_policy(self):
        """A well-formed policy with no issues should produce an empty report."""
        d = ConflictDetector()
        policy = ast.Policy(statements=[
            ast.Permission(name="read_data"),
            ast.Permission(name="write_data"),
            ast.Role(name="Viewer", permissions=["read_data"]),
            ast.Role(name="Editor", parents=["Viewer"], permissions=["write_data"]),
            ast.User(name="alice", roles=["Editor"]),
            ast.User(name="bob", roles=["Viewer"]),
        ])
        report = d.analyse(policy)
        self.assertFalse(report.has_issues)


if __name__ == "__main__":
    unittest.main(verbosity=2)
