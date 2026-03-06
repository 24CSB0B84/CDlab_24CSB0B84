"""
symbol_table.py  –  Week 7: Symbol Table for RBAC Policy Compiler
=================================================================
Maintains three separate symbol tables:
  • roles       – name -> Role AST node
  • permissions – name -> Permission AST node
  • users       – name -> User AST node
"""

from typing import Dict, Optional
import ast_nodes as ast


class SymbolTable:
    """
    A three-part symbol table that tracks every declared
    Role, Permission, and User in an RBAC policy.
    """

    def __init__(self):
        self.roles: Dict[str, ast.Role] = {}
        self.permissions: Dict[str, ast.Permission] = {}
        self.users: Dict[str, ast.User] = {}

    # ------------------------------------------------------------------
    # Insertion helpers
    # ------------------------------------------------------------------

    def add_role(self, node: ast.Role) -> bool:
        """Register a role. Returns False if the name was already present."""
        if node.name in self.roles:
            return False
        self.roles[node.name] = node
        return True

    def add_permission(self, node: ast.Permission) -> bool:
        """Register a permission. Returns False if already present."""
        if node.name in self.permissions:
            return False
        self.permissions[node.name] = node
        return True

    def add_user(self, node: ast.User) -> bool:
        """Register a user. Returns False if already present."""
        if node.name in self.users:
            return False
        self.users[node.name] = node
        return True

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def lookup_role(self, name: str) -> Optional[ast.Role]:
        return self.roles.get(name)

    def lookup_permission(self, name: str) -> Optional[ast.Permission]:
        return self.permissions.get(name)

    def lookup_user(self, name: str) -> Optional[ast.User]:
        return self.users.get(name)

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def display(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("  SYMBOL TABLE")
        lines.append("=" * 60)

        lines.append(f"\n  [PERMISSIONS]  ({len(self.permissions)} defined)")
        if self.permissions:
            for pname in sorted(self.permissions):
                lines.append(f"    • {pname}")
        else:
            lines.append("    (none)")

        lines.append(f"\n  [ROLES]  ({len(self.roles)} defined)")
        for rname, role in sorted(self.roles.items()):
            parents_str = f"  inherits: {role.parents}" if role.parents else ""
            perms_str   = f"  perms: {role.permissions}" if role.permissions else ""
            lines.append(f"    • {rname:<20}{parents_str}{perms_str}")

        lines.append(f"\n  [USERS]  ({len(self.users)} defined)")
        for uname, user in sorted(self.users.items()):
            lines.append(f"    • {uname:<20}  roles: {user.roles}")

        lines.append("=" * 60)
        return "\n".join(lines)
