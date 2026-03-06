"""
conflict_detector.py  –  Week 7: Role Conflict Detection Module
===============================================================
Analyses a parsed RBAC Policy AST using a SymbolTable and detects:

  1. Duplicate symbol definitions  (ERROR)
  2. Unknown role references        (ERROR)
  3. Cyclic role inheritance        (ERROR)
  4. Separation-of-Duty (SoD)
       a. Direct role conflict      (CONFLICT)
       b. Inherited role conflict   (CONFLICT)
  5. Redundant permissions in
       role hierarchies             (WARNING)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Tuple, Set, Dict
from collections import defaultdict

import ast_nodes as ast
from symbol_table import SymbolTable


# ──────────────────────────────────────────────────────────────────────
#  Data structures
# ──────────────────────────────────────────────────────────────────────

@dataclass
class ConflictReport:
    """Structured result returned by ConflictDetector.analyse()."""
    errors:    List[str] = field(default_factory=list)   # hard errors
    conflicts: List[str] = field(default_factory=list)   # SoD violations
    warnings:  List[str] = field(default_factory=list)   # redundant perms

    @property
    def has_issues(self) -> bool:
        return bool(self.errors or self.conflicts or self.warnings)

    def display(self) -> str:
        lines: List[str] = []

        if self.errors:
            lines.append("\n  [ERRORS]")
            for e in self.errors:
                lines.append(f"    ✗ {e}")

        if self.conflicts:
            lines.append("\n  [SoD CONFLICTS]")
            for c in self.conflicts:
                lines.append(f"    ⚡ {c}")

        if self.warnings:
            lines.append("\n  [WARNINGS]")
            for w in self.warnings:
                lines.append(f"    ⚠ {w}")

        if not lines:
            lines.append("\n  ✓ No conflicts or errors detected.")

        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
#  Conflict Detector
# ──────────────────────────────────────────────────────────────────────

class ConflictDetector:
    """
    Two-pass conflict detector:
      Pass 1 – populate the SymbolTable from the AST.
      Pass 2 – run all conflict checks.
    """

    def __init__(self):
        self.symbol_table = SymbolTable()
        self._sod_constraints: List[Tuple[str, str]] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyse(self, policy: ast.Policy) -> ConflictReport:
        """Run both passes and return a ConflictReport."""
        report = ConflictReport()
        self._pass1_build_tables(policy, report)
        self._pass2_detect_conflicts(report)
        return report

    # ------------------------------------------------------------------
    # Pass 1: Build symbol table
    # ------------------------------------------------------------------

    def _pass1_build_tables(self, policy: ast.Policy, report: ConflictReport):
        for stmt in policy.statements:
            if isinstance(stmt, ast.Permission):
                if not self.symbol_table.add_permission(stmt):
                    report.errors.append(
                        f"Duplicate permission definition: '{stmt.name}'")

            elif isinstance(stmt, ast.Role):
                if not self.symbol_table.add_role(stmt):
                    report.errors.append(
                        f"Duplicate role definition: '{stmt.name}'")

            elif isinstance(stmt, ast.User):
                if not self.symbol_table.add_user(stmt):
                    report.errors.append(
                        f"Duplicate user definition: '{stmt.name}'")

            elif isinstance(stmt, ast.Conflict):
                self._sod_constraints.append((stmt.role1, stmt.role2))

    # ------------------------------------------------------------------
    # Pass 2: Checks
    # ------------------------------------------------------------------

    def _pass2_detect_conflicts(self, report: ConflictReport):
        self._check_unknown_references(report)
        self._check_cyclic_inheritance(report)
        self._detect_sod_violations(report)
        self._detect_redundant_permissions(report)

    # ── 2a: Unknown references ─────────────────────────────────────────

    def _check_unknown_references(self, report: ConflictReport):
        # Parents of roles
        for rname, role in self.symbol_table.roles.items():
            for parent in role.parents:
                if parent not in self.symbol_table.roles:
                    report.errors.append(
                        f"Role '{rname}' inherits from unknown role '{parent}'")

        # Roles assigned to users
        for uname, user in self.symbol_table.users.items():
            for rname in user.roles:
                if rname not in self.symbol_table.roles:
                    report.errors.append(
                        f"User '{uname}' assigned to unknown role '{rname}'")

        # SoD constraint roles
        for r1, r2 in self._sod_constraints:
            for r in (r1, r2):
                if r not in self.symbol_table.roles:
                    report.errors.append(
                        f"SoD constraint references unknown role '{r}'")

    # ── 2b: Cyclic inheritance ─────────────────────────────────────────

    def _check_cyclic_inheritance(self, report: ConflictReport):
        visited: Set[str] = set()
        path:    Set[str] = set()
        reported: Set[str] = set()

        def dfs(role_name: str):
            visited.add(role_name)
            path.add(role_name)

            role = self.symbol_table.lookup_role(role_name)
            if role:
                for parent in role.parents:
                    if parent in path and parent not in reported:
                        report.errors.append(
                            f"Cyclic inheritance detected involving role '{role_name}' -> '{parent}'")
                        reported.add(parent)
                    elif parent not in visited:
                        dfs(parent)

            path.discard(role_name)

        for rname in self.symbol_table.roles:
            if rname not in visited:
                dfs(rname)

    # ── 2c: SoD violations ─────────────────────────────────────────────

    def _get_effective_roles(self, user: ast.User) -> Set[str]:
        """Expand direct roles into the full set (including inherited)."""
        effective: Set[str] = set()

        def traverse(rname: str):
            if rname in effective:
                return
            effective.add(rname)
            role = self.symbol_table.lookup_role(rname)
            if role:
                for parent in role.parents:
                    traverse(parent)

        for rname in user.roles:
            traverse(rname)

        return effective

    def _detect_sod_violations(self, report: ConflictReport):
        for uname, user in self.symbol_table.users.items():
            effective = self._get_effective_roles(user)

            for r1, r2 in self._sod_constraints:
                if r1 in effective and r2 in effective:
                    # Determine if this is direct or inherited
                    direct = set(user.roles)
                    if r1 in direct and r2 in direct:
                        detail = "direct assignment"
                    else:
                        detail = "via role inheritance"

                    report.conflicts.append(
                        f"User '{uname}' violates SoD: holds conflicting "
                        f"roles '{r1}' and '{r2}' ({detail})")

    # ── 2d: Redundant permissions ──────────────────────────────────────

    def _get_inherited_permissions(self, role_name: str,
                                   visited: Set[str] = None) -> Set[str]:
        """Recursively collect all permissions inherited from parent roles."""
        if visited is None:
            visited = set()
        if role_name in visited:
            return set()
        visited.add(role_name)

        role = self.symbol_table.lookup_role(role_name)
        if not role:
            return set()

        inherited: Set[str] = set()
        for parent in role.parents:
            parent_own = set()
            prole = self.symbol_table.lookup_role(parent)
            if prole:
                parent_own = set(prole.permissions)
            parent_inherited = self._get_inherited_permissions(parent, visited)
            inherited |= parent_own | parent_inherited

        return inherited

    def _detect_redundant_permissions(self, report: ConflictReport):
        for rname, role in self.symbol_table.roles.items():
            if not role.parents:
                continue
            inherited = self._get_inherited_permissions(rname)
            for p in role.permissions:
                if p in inherited:
                    report.warnings.append(
                        f"Role '{rname}' has redundant permission '{p}' "
                        f"(already inherited from a parent role)")
