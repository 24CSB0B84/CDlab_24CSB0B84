import unittest
import ast_nodes as ast
from semantic_analyzer import SemanticAnalyzer

class TestSemanticAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = SemanticAnalyzer()

    def test_no_conflicts(self):
        # valid policy
        # role r1 { permissions p1; }
        # user u1 engages r1;
        policy = ast.Policy(statements=[
            ast.Role(name='r1', permissions=['p1']),
            ast.User(name='u1', roles=['r1'])
        ])
        self.analyzer.visit(policy)
        self.assertEqual(self.analyzer.errors, [])

    def test_unknown_role(self):
        policy = ast.Policy(statements=[
             ast.User(name='u1', roles=['unknown_role'])
        ])
        self.analyzer.visit(policy)
        self.assertTrue(any("unknown role 'unknown_role'" in e for e in self.analyzer.errors))

    def test_sod_conflict(self):
        # role A, role B
        # conflict A and B
        # user u1 engages A, B
        policy = ast.Policy(statements=[
            ast.Role(name='A'),
            ast.Role(name='B'),
            ast.Conflict(role1='A', role2='B'),
            ast.User(name='u1', roles=['A', 'B'])
        ])
        self.analyzer.visit(policy)
        self.assertTrue(any("conflicting roles 'A' and 'B'" in e for e in self.analyzer.errors))
        
    def test_sod_conflict_inherited(self):
        # role A
        # role B inherits A
        # role C
        # conflict A and C
        # user u1 engages B, C (B implies A, so conflict A-C applies to B-C user)
        policy = ast.Policy(statements=[
            ast.Role(name='A'),
            ast.Role(name='B', parents=['A']),
            ast.Role(name='C'),
            ast.Conflict(role1='A', role2='C'),
            ast.User(name='u1', roles=['B', 'C'])
        ])
        self.analyzer.visit(policy)
        self.assertTrue(any("conflicting roles 'A' and 'C'" in e for e in self.analyzer.errors))

    def test_redundant_permission(self):
        # role A { permissions p1; }
        # role B inherits A { permissions p1; }
        policy = ast.Policy(statements=[
            ast.Role(name='A', permissions=['p1']),
            ast.Role(name='B', parents=['A'], permissions=['p1'])
        ])
        self.analyzer.visit(policy)
        self.assertTrue(any("redundant permission 'p1'" in e for e in self.analyzer.errors))

    def test_cyclic_inheritance(self):
        # role A inherits B; role B inherits A;
        policy = ast.Policy(statements=[
            ast.Role(name='A', parents=['B']),
            ast.Role(name='B', parents=['A'])
        ])
        self.analyzer.visit(policy)
        self.assertTrue(any("Cyclic inheritance" in e for e in self.analyzer.errors))

if __name__ == '__main__':
    unittest.main()
