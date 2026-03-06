from typing import List, Dict, Set, Tuple
from collections import defaultdict
import ast_nodes as ast

class SemanticAnalyzer:
    def __init__(self):
        self.roles: Dict[str, ast.Role] = {}
        self.users: Dict[str, ast.User] = {}
        self.permissions: Set[str] = set()
        self.sod_constraints: List[Tuple[str, str]] = []
        self.errors: List[str] = []

    def visit(self, node: ast.Node):
        """Generic visitor method."""
        if isinstance(node, ast.Policy):
            self.visit_policy(node)
        elif isinstance(node, ast.Role):
            self.visit_role(node)
        elif isinstance(node, ast.User):
            self.visit_user(node)
        elif isinstance(node, ast.Permission):
            self.visit_permission(node)
        elif isinstance(node, ast.Conflict):
            self.visit_conflict(node)

    def visit_policy(self, node: ast.Policy):
        # First pass: Collect all definitions
        for stmt in node.statements:
            self.visit(stmt)
        
        # Second pass: Analyze
        self.check_unknown_references()
        self.check_cyclic_inheritance()
        self.detect_sod_violations()
        self.detect_redundant_permissions()

    def visit_role(self, node: ast.Role):
        if node.name in self.roles:
            self.errors.append(f"Error: Duplicate role definition '{node.name}'.")
        self.roles[node.name] = node

    def visit_user(self, node: ast.User):
        if node.name in self.users:
            self.errors.append(f"Error: Duplicate user definition '{node.name}'.")
        self.users[node.name] = node

    def visit_permission(self, node: ast.Permission):
        self.permissions.add(node.name)

    def visit_conflict(self, node: ast.Conflict):
        self.sod_constraints.append((node.role1, node.role2))

    def check_unknown_references(self):
        # Check role parents
        for role_name, role_node in self.roles.items():
            for parent in role_node.parents:
                if parent not in self.roles:
                    self.errors.append(f"Error: Role '{role_name}' inherits from unknown role '{parent}'.")
        
        # Check user role assignments
        for user_name, user_node in self.users.items():
            for role in user_node.roles:
                if role not in self.roles:
                    self.errors.append(f"Error: User '{user_name}' assigned to unknown role '{role}'.")

        # Check permission references in roles (if we want to be strict)
        # Note: The lexer/parser treats PERMISSION definitions separately from usage in roles.
        # Ideally, we should check if permissions used in roles are defined.
        # But for now, we'll assume permissions are string literals. (If we were strict, we'd check against self.permissions)

    def check_cyclic_inheritance(self):
        visited = set()
        path = set()

        def dfs(role_name):
            visited.add(role_name)
            path.add(role_name)
            
            if role_name in self.roles:
                for parent in self.roles[role_name].parents:
                    if parent in path:
                         self.errors.append(f"Error: Cyclic inheritance detected involving role '{role_name}'.")
                    elif parent not in visited:
                        dfs(parent)
            
            path.remove(role_name)

        for role_name in self.roles:
            if role_name not in visited:
                dfs(role_name)

    def get_effective_roles(self, user: ast.User) -> Set[str]:
        """Returns all roles a user has, including inherited ones."""
        effective_roles = set()
        
        def traverse(role_name):
            if role_name in effective_roles:
                return
            effective_roles.add(role_name)
            if role_name in self.roles:
                for parent in self.roles[role_name].parents:
                    traverse(parent)

        for role_name in user.roles:
            traverse(role_name)
            
        return effective_roles

    def detect_sod_violations(self):
        for user_name, user_node in self.users.items():
            effective_roles = self.get_effective_roles(user_node)
            
            for r1, r2 in self.sod_constraints:
                if r1 in effective_roles and r2 in effective_roles:
                    self.errors.append(f"Conflict: User '{user_name}' has conflicting roles '{r1}' and '{r2}'.")

    def detect_redundant_permissions(self):
        # Map: role -> set of effective permissions
        role_permissions = {} 

        def get_permissions(role_name, visited_roles=None):
            if visited_roles is None:
                visited_roles = set()
            
            if role_name in visited_roles:
                return set() # Cycle already handled
            visited_roles.add(role_name)

            if role_name not in self.roles:
                return set()
            
            role_node = self.roles[role_name]
            perms = set(role_node.permissions)
            
            for parent in role_node.parents:
                parent_perms = get_permissions(parent, visited_roles)
                
                # Check for redundancy: direct permission already in parent?
                for p in perms:
                    if p in parent_perms:
                         # This is a bit noisy if we report it for every parent, but it's a redundancy
                         pass 
                         # We could strictly report it here, but let's aggregate first.
                
                perms.update(parent_perms)
            
            return perms

        for role_name, role_node in self.roles.items():
             # Basic check: Explicit permission also inherited?
             inherited_perms = set()
             for parent in role_node.parents:
                 inherited_perms.update(get_permissions(parent))
            
             for p in role_node.permissions:
                 if p in inherited_perms:
                     self.errors.append(f"Warning: Role '{role_name}' has redundant permission '{p}' (already inherited).")

