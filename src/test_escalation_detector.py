
import unittest
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import ast_nodes as ast
from escalation_detector import EscalationDetector, DANGEROUS_COMBOS


def _make_policy(*statements):
    return ast.Policy(statements=list(statements))


# ─────────────────────────────────────────────────────────────────────────────
#  Symbol Table Population
# ─────────────────────────────────────────────────────────────────────────────

class TestSymbolTableBuilding(unittest.TestCase):

    def test_roles_and_permissions_registered(self):
        d = EscalationDetector()
        policy = _make_policy(
            ast.Permission(name="read_data"),
            ast.Role(name="Viewer", permissions=["read_data"]),
        )
        d.analyse(policy)
        self.assertIn("Viewer", d.symbol_table.roles)
        self.assertIn("read_data", d.symbol_table.permissions)

    def test_users_registered(self):
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Admin"),
            ast.User(name="alice", roles=["Admin"]),
        )
        d.analyse(policy)
        self.assertIn("alice", d.symbol_table.users)


# ─────────────────────────────────────────────────────────────────────────────
#  Role Hierarchy Graph
# ─────────────────────────────────────────────────────────────────────────────

class TestHierarchyGraph(unittest.TestCase):

    def test_single_inheritance_edge(self):
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Base"),
            ast.Role(name="Child", parents=["Base"]),
        )
        report = d.analyse(policy)
        self.assertIn(("Child", "Base"), report.graph_edges)

    def test_multi_level_edges(self):
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Level1"),
            ast.Role(name="Level2", parents=["Level1"]),
            ast.Role(name="Level3", parents=["Level2"]),
        )
        report = d.analyse(policy)
        self.assertIn(("Level2", "Level1"), report.graph_edges)
        self.assertIn(("Level3", "Level2"), report.graph_edges)

    def test_no_edges_for_flat_roles(self):
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="A"),
            ast.Role(name="B"),
        )
        report = d.analyse(policy)
        self.assertEqual(report.graph_edges, [])

    def test_unknown_parent_generates_warning(self):
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Child", parents=["Ghost"]),
        )
        report = d.analyse(policy)
        self.assertTrue(any("Ghost" in w for w in report.warnings))


# ─────────────────────────────────────────────────────────────────────────────
#  Privilege Escalation Paths
# ─────────────────────────────────────────────────────────────────────────────

class TestEscalationPaths(unittest.TestCase):

    def test_single_hop_escalation(self):
        """Child inheriting parent gains parent permissions."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Intern", permissions=["read_data"]),
            ast.Role(name="Developer", parents=["Intern"], permissions=["write_data"]),
        )
        report = d.analyse(policy)
        paths = [(ep.from_role, ep.to_role) for ep in report.escalation_paths]
        self.assertIn(("Developer", "Intern"), paths)

    def test_multi_hop_escalation_path(self):
        """Three-level hierarchy: Intern -> Developer -> Admin."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Intern", permissions=["read_data"]),
            ast.Role(name="Developer", parents=["Intern"], permissions=["write_data"]),
            ast.Role(name="Admin", parents=["Developer"], permissions=["delete_data"]),
        )
        report = d.analyse(policy)
        # Developer->Intern and Admin->Developer and Admin->Intern should all appear
        paths = [(ep.from_role, ep.to_role) for ep in report.escalation_paths]
        self.assertIn(("Developer", "Intern"), paths)
        self.assertIn(("Admin", "Developer"), paths)

    def test_no_escalation_for_flat_roles(self):
        """Roles with no inheritance produce zero escalation paths."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="A", permissions=["p1"]),
            ast.Role(name="B", permissions=["p2"]),
        )
        report = d.analyse(policy)
        self.assertEqual(report.escalation_paths, [])

    def test_permissions_gained_correctly(self):
        """Gained permissions list should contain parent-only perms."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Reader", permissions=["read_data"]),
            ast.Role(name="Writer", parents=["Reader"], permissions=["write_data"]),
        )
        report = d.analyse(policy)
        writer_to_reader = [ep for ep in report.escalation_paths
                            if ep.from_role == "Writer" and ep.to_role == "Reader"]
        self.assertTrue(writer_to_reader)
        self.assertIn("read_data", writer_to_reader[0].gained_perms)


# ─────────────────────────────────────────────────────────────────────────────
#  Dangerous Permission Combinations
# ─────────────────────────────────────────────────────────────────────────────

class TestDangerousCombinations(unittest.TestCase):

    def test_user_with_dangerous_combo(self):
        """User whose effective permissions include a dangerous pair."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Trader", permissions=["execute_trades"]),
            ast.Role(name="Approver", permissions=["approve_trades"]),
            ast.User(name="eve", roles=["Trader", "Approver"]),
        )
        report = d.analyse(policy)
        self.assertTrue(any("eve" in c for c in report.dangerous_combos_found))

    def test_user_with_inherited_dangerous_combo(self):
        """User inherits dangerous perms through role hierarchy."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Base", permissions=["execute_trades"]),
            ast.Role(name="Senior", parents=["Base"], permissions=["approve_trades"]),
            ast.User(name="frank", roles=["Senior"]),
        )
        report = d.analyse(policy)
        self.assertTrue(any("frank" in c for c in report.dangerous_combos_found))

    def test_clean_user_no_dangerous_combo(self):
        """User with only safe permissions should not be flagged."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Viewer", permissions=["read_data", "read_reports"]),
            ast.User(name="grace", roles=["Viewer"]),
        )
        report = d.analyse(policy)
        user_flags = [c for c in report.dangerous_combos_found if "grace" in c]
        self.assertEqual(user_flags, [])

    def test_role_level_dangerous_combo_detected(self):
        """Dangerous combo should be flagged even without an assigned user."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="Risky", permissions=["write_data", "delete_data"]),
        )
        report = d.analyse(policy)
        self.assertTrue(any("Risky" in c for c in report.dangerous_combos_found))

    def test_no_false_positive_for_single_perm(self):
        """A role with only one permission from a dangerous pair is safe."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Role(name="SafeRole", permissions=["write_data"]),
            ast.User(name="bob", roles=["SafeRole"]),
        )
        report = d.analyse(policy)
        user_flags = [c for c in report.dangerous_combos_found if "bob" in c]
        self.assertEqual(user_flags, [])


# ─────────────────────────────────────────────────────────────────────────────
#  Clean Policy
# ─────────────────────────────────────────────────────────────────────────────

class TestCleanPolicy(unittest.TestCase):

    def test_fully_clean_flat_policy(self):
        """A flat policy with no inheritance and no dangerous combos."""
        d = EscalationDetector()
        policy = _make_policy(
            ast.Permission(name="read_data"),
            ast.Role(name="Viewer", permissions=["read_data"]),
            ast.User(name="alice", roles=["Viewer"]),
        )
        report = d.analyse(policy)
        self.assertEqual(report.escalation_paths, [])
        self.assertEqual(report.dangerous_combos_found, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
