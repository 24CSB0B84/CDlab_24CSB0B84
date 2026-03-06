"""
escalation_detector.py  –  Week 8: Privilege Escalation Detection Module
=========================================================================
Analyses a parsed RBAC Policy AST (via the Week 7 SymbolTable) and detects:

  1. Builds a Role Hierarchy Graph (directed edges: child -> parent)
  2. Detects static privilege escalation paths
       – A lower-privilege role can reach a higher-privilege role's
         permissions purely through inheritance / assignment chains
  3. Identifies dangerous permission combinations held by a single user
       (e.g. write + approve, delete + admin, execute + approve)

Output is a structured EscalationReport.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict, deque

import ast_nodes as ast
from symbol_table import SymbolTable


# ─────────────────────────────────────────────────────────────────────────────
#  Configuration: Dangerous permission combinations
# ─────────────────────────────────────────────────────────────────────────────

# Each tuple = a pair of permissions whose simultaneous possession is dangerous.
# The analyst can extend this list freely.
DANGEROUS_COMBOS: List[Tuple[str, str]] = [
    # Financial / trading
    ("execute_trades",    "approve_trades"),
    ("write_financials",  "approve_trades"),
    # Data integrity
    ("write_data",        "delete_data"),
    ("write_data",        "approve_data"),
    # Admin abuse
    ("admin_users",       "audit_log"),
    ("admin_users",       "write_financials"),
    # Generic escalation pairs
    ("write",             "delete"),
    ("write",             "approve"),
    ("execute",           "approve"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EscalationPath:
    """Represents a discovered privilege escalation path."""
    from_role:   str
    to_role:     str
    path:        List[str]         # ordered list of role names
    gained_perms: List[str]        # permissions newly reachable at 'to_role'

    def __str__(self) -> str:
        arrow = " -> ".join(self.path)
        perms = ", ".join(self.gained_perms) if self.gained_perms else "(all parent perms)"
        return f"{arrow}  [gains: {perms}]"


@dataclass
class EscalationReport:
    """Structured result returned by EscalationDetector.analyse()."""
    graph_edges:           List[Tuple[str, str]]  = field(default_factory=list)
    escalation_paths:      List[EscalationPath]   = field(default_factory=list)
    dangerous_combos_found: List[str]             = field(default_factory=list)
    warnings:              List[str]              = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return bool(self.escalation_paths or self.dangerous_combos_found or self.warnings)

    def display(self) -> str:
        lines: List[str] = []

        # ── Role Hierarchy Graph ──────────────────────────────────────
        lines.append("\n  [ROLE HIERARCHY GRAPH]")
        if self.graph_edges:
            for child, parent in sorted(self.graph_edges):
                lines.append(f"    {child:<20} ──inherits──>  {parent}")
        else:
            lines.append("    (no inheritance relationships)")

        # ── Escalation Paths ─────────────────────────────────────────
        lines.append(f"\n  [PRIVILEGE ESCALATION PATHS]  ({len(self.escalation_paths)} found)")
        if self.escalation_paths:
            for ep in self.escalation_paths:
                lines.append(f"    ↑ {ep}")
        else:
            lines.append("    ✓ No escalation paths detected.")

        # ── Dangerous Combos ─────────────────────────────────────────
        lines.append(f"\n  [DANGEROUS PERMISSION COMBINATIONS]  "
                     f"({len(self.dangerous_combos_found)} found)")
        if self.dangerous_combos_found:
            for d in self.dangerous_combos_found:
                lines.append(f"    ⚠ {d}")
        else:
            lines.append("    ✓ No dangerous permission combinations detected.")

        # ── Warnings ─────────────────────────────────────────────────
        if self.warnings:
            lines.append("\n  [OTHER WARNINGS]")
            for w in self.warnings:
                lines.append(f"    ! {w}")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  Privilege Escalation Detector
# ─────────────────────────────────────────────────────────────────────────────

class EscalationDetector:
    """
    Three-phase detector:
      Phase 1 – Populate SymbolTable from policy AST.
      Phase 2 – Build role hierarchy graph.
      Phase 3 – Detect escalation paths and dangerous combos.
    """

    def __init__(self):
        self.symbol_table = SymbolTable()
        # Adjacency: child_role -> set of parent_roles (inheritance direction)
        self._graph: Dict[str, Set[str]] = defaultdict(set)

    # ── Public entry point ────────────────────────────────────────────────────

    def analyse(self, policy: ast.Policy) -> EscalationReport:
        report = EscalationReport()
        self._build_symbol_table(policy)
        self._build_graph(report)
        self._detect_escalation_paths(report)
        self._detect_dangerous_combos(report)
        return report

    # ── Phase 1: Symbol table ─────────────────────────────────────────────────

    def _build_symbol_table(self, policy: ast.Policy):
        for stmt in policy.statements:
            if isinstance(stmt, ast.Permission):
                self.symbol_table.add_permission(stmt)
            elif isinstance(stmt, ast.Role):
                self.symbol_table.add_role(stmt)
            elif isinstance(stmt, ast.User):
                self.symbol_table.add_user(stmt)

    # ── Phase 2: Build role hierarchy graph ───────────────────────────────────

    def _build_graph(self, report: EscalationReport):
        """
        Directed edge: child ──inherits──> parent
        A child role 'escalates' to its parent because it gains all parent perms.
        """
        for rname, role in self.symbol_table.roles.items():
            for parent in role.parents:
                if parent in self.symbol_table.roles:
                    self._graph[rname].add(parent)
                    report.graph_edges.append((rname, parent))
                else:
                    report.warnings.append(
                        f"Role '{rname}' inherits from unknown role '{parent}' (skipped in graph)")

    # ── Phase 3a: Detect escalation paths ─────────────────────────────────────

    def _get_all_permissions(self, role_name: str,
                              visited: Set[str] = None) -> Set[str]:
        """Recursively collect all permissions available to a role (own + inherited)."""
        if visited is None:
            visited = set()
        if role_name in visited:
            return set()
        visited.add(role_name)

        role = self.symbol_table.lookup_role(role_name)
        if not role:
            return set()

        perms: Set[str] = set(role.permissions)
        for parent in role.parents:
            perms |= self._get_all_permissions(parent, visited)
        return perms

    def _bfs_paths(self, start: str) -> List[List[str]]:
        """BFS to find all simple paths from 'start' following inheritance edges."""
        paths = []
        queue: deque = deque([[start]])
        while queue:
            path = queue.popleft()
            current = path[-1]
            # If this node has no further edges in the graph, it's a terminal
            if current not in self._graph or not self._graph[current]:
                if len(path) > 1:
                    paths.append(path)
            else:
                for parent in self._graph[current]:
                    if parent not in path:  # avoid cycles
                        queue.append(path + [parent])
                        if len(path) > 1:
                            paths.append(path)  # intermediate paths too
        return paths

    def _detect_escalation_paths(self, report: EscalationReport):
        """
        For every role that inherits from any other role, compute the
        permissions gained through the escalation and report the path.
        We report a path (A -> B) when:
          • A directly has fewer permissions than A+B combined, AND
          • A has at least one parent (B) reachable through inheritance.
        We avoid duplicating single-hop paths that are already trivially visible.
        """
        reported: Set[Tuple[str, str]] = set()

        for rname in self.symbol_table.roles:
            if rname not in self._graph:
                continue  # no inheritance, no escalation from this role

            # Permissions the role has on its own (without inheritance)
            role_own_perms: Set[str] = set(self.symbol_table.roles[rname].permissions)

            # All paths reachable from this role
            paths = self._bfs_paths(rname)

            for path in paths:
                from_r = path[0]
                to_r   = path[-1]
                key    = (from_r, to_r)
                if key in reported:
                    continue
                reported.add(key)

                # Permissions gained purely from the escalation target
                target_perms = self._get_all_permissions(to_r)
                gained = sorted(target_perms - role_own_perms)

                if gained or target_perms:
                    ep = EscalationPath(
                        from_role=from_r,
                        to_role=to_r,
                        path=path,
                        gained_perms=gained
                    )
                    report.escalation_paths.append(ep)

    # ── Phase 3b: Dangerous permission combinations ────────────────────────────

    def _get_user_permissions(self, user: ast.User) -> Set[str]:
        """Collect all effective permissions for a user across all their roles."""
        all_perms: Set[str] = set()
        visited_roles: Set[str] = set()

        def traverse(rname: str):
            if rname in visited_roles:
                return
            visited_roles.add(rname)
            role = self.symbol_table.lookup_role(rname)
            if role:
                all_perms.update(role.permissions)
                for parent in role.parents:
                    traverse(parent)

        for rname in user.roles:
            traverse(rname)
        return all_perms

    def _detect_dangerous_combos(self, report: EscalationReport):
        """
        Check each user's effective permission set against known dangerous pairs.
        Also checks every individual role's effective permissions.
        """
        # Per-user check
        for uname, user in self.symbol_table.users.items():
            user_perms = self._get_user_permissions(user)

            for p1, p2 in DANGEROUS_COMBOS:
                if p1 in user_perms and p2 in user_perms:
                    report.dangerous_combos_found.append(
                        f"User '{uname}' holds dangerous combination: "
                        f"'{p1}' + '{p2}'")

        # Per-role check (catches role-level danger even if no user assigned)
        reported_roles: Set[str] = set()
        for rname in self.symbol_table.roles:
            role_perms = self._get_all_permissions(rname)
            for p1, p2 in DANGEROUS_COMBOS:
                if p1 in role_perms and p2 in role_perms:
                    key = f"{rname}:{p1}+{p2}"
                    if key not in reported_roles:
                        reported_roles.add(key)
                        report.dangerous_combos_found.append(
                            f"Role '{rname}' (effective) holds dangerous combination: "
                            f"'{p1}' + '{p2}'")
