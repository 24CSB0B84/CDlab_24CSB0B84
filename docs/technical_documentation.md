# RBAC Policy DSL Compiler — Technical Documentation

> **Week 12 Deliverable | Compiler Design Lab**  
> Version: 1.0 | Language: Python 3.10+ | Parser: PLY (LALR(1))

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Module Reference](#2-module-reference)
3. [Data Structures](#3-data-structures)
4. [Compiler Phases — Technical Detail](#4-compiler-phases--technical-detail)
5. [Error Types & Detection Algorithms](#5-error-types--detection-algorithms)
6. [Detected Security Issues — Documented Cases](#6-detected-security-issues--documented-cases)
7. [API Reference](#7-api-reference)
8. [Configuration & Extension Points](#8-configuration--extension-points)

---

## 1. System Architecture

The compiler is a **multi-phase pipeline** implemented as independent Python modules, each representing one classical compiler stage. Phases communicate through structured data objects rather than raw strings, making the pipeline testable and reusable as a library.

```
         ┌────────────────────────────────────────────────┐
         │             RBACCompiler.compile()             │
         └────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────────┐
          ▼                   ▼                         ▼
   ┌─────────────┐   ┌──────────────┐       ┌──────────────────┐
   │  lexer.py   │──▶│  parser.py   │──────▶│ semantic_analyzer│
   │  (PLY lex)  │   │  (PLY yacc)  │  AST  │   .py            │
   └─────────────┘   └──────────────┘       └──────────────────┘
                                                       │
                                    ┌──────────────────┼──────────────────┐
                                    ▼                                       ▼
                          ┌─────────────────────┐             ┌────────────────────────┐
                          │ conflict_detector.py │             │ escalation_detector.py │
                          │ (SoD, cycles, refs,  │             │ (graph traversal,      │
                          │  redundancy)         │             │  dangerous combos)     │
                          └─────────────────────┘             └────────────────────────┘
                                    │                                       │
                                    └──────────────┬────────────────────────┘
                                                   ▼
                                        ┌──────────────────────┐
                                        │  report_generator.py │
                                        │  (Markdown + Mermaid)│
                                        └──────────────────────┘
```

### Inter-phase Data Flow

| From Phase | To Phase | Object Passed |
|---|---|---|
| lexer.py | parser.py | PLY token stream |
| parser.py | semantic_analyzer.py | `ast_nodes.Policy` (AST root) |
| semantic_analyzer.py | conflict_detector.py | `ast_nodes.Policy` + populated `SymbolTable` |
| conflict_detector.py | escalation_detector.py | `ast_nodes.Policy` |
| All phases | rbac_compiler.py | `CompilerResult` bundle |
| CompilerResult | report_generator.py | `CompilerResult` |

---

## 2. Module Reference

### `src/lexer.py` — Lexical Analyser

Converts raw `.rbac` source text into a PLY token stream using regular expressions.

**Token Types:**

| Token | Pattern | Example Match |
|---|---|---|
| `ROLE` | `role` (reserved) | `role` |
| `PERMISSION` | `permission` (reserved) | `permission` |
| `USER` | `user` (reserved) | `user` |
| `CONFLICT` | `conflict` (reserved) | `conflict` |
| `INHERITS` | `inherits` (reserved) | `inherits` |
| `PERMISSIONS` | `permissions` (reserved) | `permissions` |
| `ENGAGES` | `engages` (reserved) | `engages` |
| `AND` | `and` (reserved) | `and` |
| `ID` | `[a-zA-Z_][a-zA-Z0-9_]*` | `alice`, `read_data`, `Admin` |
| `LBRACE` | `\{` | `{` |
| `RBRACE` | `\}` | `}` |
| `SEMI` | `;` | `;` |
| `COMMA` | `,` | `,` |

Reserved words are matched first through the `reserved` dictionary; any other identifier becomes `ID`.

---

### `src/ast_nodes.py` — AST Node Definitions

Python `dataclass` hierarchy representing the policy's structure.

| Class | Fields | Represents |
|---|---|---|
| `Node` | — | Abstract base |
| `Policy` | `statements: List[Node]` | Root node; the entire policy |
| `Permission` | `name: str` | `permission read_data;` |
| `Role` | `name: str`, `parents: List[str]`, `permissions: List[str]` | A role definition block |
| `User` | `name: str`, `roles: List[str]` | A user assignment |
| `Conflict` | `role1: str`, `role2: str` | An SoD constraint |

---

### `src/parser.py` — Syntax Analyser

LALR(1) parser built with PLY yacc. Each grammar rule is a Python function whose docstring is the BNF rule.

**Grammar summary:**
```
policy         → statement_list
statement_list → statement statement_list | statement
statement      → role_def | perm_def | user_def | sod_def
perm_def       → PERMISSION ID SEMI
role_def       → ROLE ID LBRACE role_body RBRACE
role_body      → role_attr role_body | ε
role_attr      → INHERITS id_list SEMI | PERMISSIONS id_list SEMI
user_def       → USER ID ENGAGES id_list SEMI
sod_def        → CONFLICT ID AND ID SEMI
id_list        → ID COMMA id_list | ID
```

**Error recovery:** `p_error` implements panic-mode recovery — on a syntax error it discards tokens until reaching `;` or `}`, then restarts the parser.

**Generated artefacts:** `parsetab.py` (parsing table cache), `parser.out` (state table dump for debugging).

---

### `src/symbol_table.py` — Symbol Table

Centralized registry for all declared names in a policy.

**Internal structure:**
```python
self.roles:       Dict[str, ast.Role]       # name → Role node
self.permissions: Dict[str, ast.Permission] # name → Permission node
self.users:       Dict[str, ast.User]       # name → User node
```

**Key methods:**

| Method | Returns | Behaviour |
|---|---|---|
| `add_role(node)` | `bool` | `False` if duplicate |
| `add_permission(node)` | `bool` | `False` if duplicate |
| `add_user(node)` | `bool` | `False` if duplicate |
| `lookup_role(name)` | `Optional[Role]` | `None` if not found |
| `lookup_permission(name)` | `Optional[Permission]` | `None` if not found |
| `lookup_user(name)` | `Optional[User]` | `None` if not found |
| `display()` | `str` | Formatted table for debugging |

---

### `src/semantic_analyzer.py` — Semantic Analyser

First semantic pass over the AST. Validates declarations before conflict detection runs.

**Checks performed:**
- Duplicate role, permission, and user names
- Permissions referenced in a role block that were never declared
- Users assigned to roles before any roles are declared (order independence via two-pass design)

**Class:** `SemanticAnalyzer`  
**Method:** `visit(policy: ast.Policy) → None`  
**Errors:** Accumulated in `self.errors: List[str]`

---

### `src/conflict_detector.py` — Conflict Detector

Core security analysis engine. Runs in two passes over the AST.

**Class:** `ConflictDetector`  
**Method:** `analyse(policy: ast.Policy) → ConflictReport`

**`ConflictReport` fields:**

| Field | Type | Contents |
|---|---|---|
| `errors` | `List[str]` | Fatal errors (unknown refs, duplicates, cycles) |
| `conflicts` | `List[str]` | SoD violations |
| `warnings` | `List[str]` | Non-fatal issues (redundant permissions) |

**Detection algorithms** — see [Section 5](#5-error-types--detection-algorithms).

---

### `src/escalation_detector.py` — Escalation Detector

Builds a directed role inheritance graph and traces privilege escalation.

**Class:** `EscalationDetector`  
**Method:** `analyse(policy: ast.Policy) → EscalationReport`

**`EscalationReport` fields:**

| Field | Type | Contents |
|---|---|---|
| `graph_edges` | `List[Tuple[str,str]]` | `(child, parent)` role pairs |
| `escalation_paths` | `List[EscalationPath]` | All detected escalation paths |
| `dangerous_combos_found` | `List[str]` | Dangerous permission combination descriptions |

**`EscalationPath` fields:**

| Field | Contents |
|---|---|
| `source_role` | Starting (low-privilege) role |
| `target_role` | Destination (high-privilege) role |
| `path` | List of role names in the escalation chain |
| `gained_permissions` | Permissions gained via escalation |

---

### `src/rbac_compiler.py` — Integrated Pipeline

Single entry point that chains all compiler phases.

**Class:** `RBACCompiler`  
**Method:** `compile(source: str) → CompilerResult`

**`CompilerResult` fields:**

| Field | Type |
|---|---|
| `parse_ok` | `bool` |
| `ast` | `ast_nodes.Policy \| None` |
| `semantic_errors` | `List[str]` |
| `conflict_report` | `ConflictReport \| None` |
| `escalation_report` | `EscalationReport \| None` |
| `total_issues` | `int` |

---

### `src/report_generator.py` — Report Generator

Converts a `CompilerResult` into a human-readable Markdown security report with Mermaid.js visualizations.

**Function:** `generate_report(result: CompilerResult, policy_path: str) → str`

**Report sections produced:**
1. Policy status summary
2. Role hierarchy Mermaid.js diagram (`graph BT`)
3. SoD conflicts in Markdown list format
4. Warnings (redundant permissions)
5. Privilege escalation paths in Markdown table

---

### `src/evaluate.py` — Evaluation Module

Runs the compiler across a set of benchmark policies and measures performance.

**Metrics computed per policy:**
- Total issues detected
- Detection time (milliseconds)
- Comparison with manual ground-truth labels
- False positive count

**Output:** `reports/evaluation_results.json`

---

## 3. Data Structures

### Role Hierarchy Graph

Represented as an **adjacency list** (directed graph) built from `Role.parents` in the AST:

```python
graph: Dict[str, List[str]] = {}
# graph["Developer"] = ["Intern"]
# graph["Admin"]     = ["Developer"]
```

Used by `EscalationDetector` to compute **transitive permission closure** via BFS.

### Effective Role Set (BFS)

For each user, the complete set of roles they effectively hold (direct + all inherited) is computed by BFS over the role hierarchy graph:

```python
def _get_effective_roles(user) -> Set[str]:
    queue = deque(user.roles)
    visited = set(user.roles)
    while queue:
        r = queue.popleft()
        role = symbol_table.lookup_role(r)
        if role:
            for parent in role.parents:
                if parent not in visited:
                    visited.add(parent)
                    queue.append(parent)
    return visited
```

### SoD Constraints

Stored as a list of tuples `(role1, role2)` collected during Pass 1 of conflict detection:
```python
_sod_constraints: List[Tuple[str, str]]
```

---

## 4. Compiler Phases — Technical Detail

### Phase 1 & 2: Lexing + Parsing

PLY's lexer scans left-to-right, matching the longest token at each position. The parser uses an LALR(1) table generated offline (cached in `parsetab.py`).

**Key implementation note:** When running the integrated compiler (`rbac_compiler.py`), a fresh PLY lexer instance is created for each call via `ply.lex.lex(module=_lexer_module)` to prevent state contamination between repeated calls.

### Phase 3: Semantic Analysis

`SemanticAnalyzer.visit()` performs a single AST walk. Errors are accumulated in `self.errors` rather than raised as exceptions, so all errors are reported together.

### Phase 4: Conflict Detection

**Two-pass design:**

| Pass | Action |
|---|---|
| Pass 1 | Walk AST; populate SymbolTable; collect SoD constraints |
| Pass 2 | Run all four checks in order |

**Check execution order:**
1. Unknown references → errors
2. Cyclic inheritance → errors  
3. SoD violations → conflicts
4. Redundant permissions → warnings

### Phase 5: Escalation Detection

1. Build role graph from `Role.parents`
2. Compute transitive permission closure for every role (BFS)
3. For each role pair `(A, B)` where B is reachable from A: if B has permissions A does not directly hold → escalation path
4. For each user: compute effective permission set and check against dangerous combo list

### Phase 6: Report Generation

`report_generator.py` reads the `CompilerResult` bundle and formats all fields into Markdown sections. Mermaid graph syntax is generated by iterating `escalation_report.graph_edges` and emitting `Child --> Parent` lines inside a `graph BT` block.

---

## 5. Error Types & Detection Algorithms

### 5.1 Unknown Reference

**Algorithm:** After Pass 1 builds the symbol table, every `Role.parents` entry and every `User.roles` entry is checked against `symbol_table.roles`. Any name not found → error.

**Complexity:** O(R·P + U·R') where R = roles, P = average parents per role, U = users, R' = average roles per user.

---

### 5.2 Cyclic Inheritance

**Algorithm:** Depth-First Search with a `visited` set and a `path` set (nodes in the current DFS stack).

```
for each role r not yet visited:
    DFS(r):
        add r to visited and path
        for each parent p of r:
            if p in path → cycle detected
            elif p not in visited → DFS(p)
        remove r from path
```

**Complexity:** O(R + E) where E = inheritance edges.

---

### 5.3 SoD Violation

**Algorithm:**
1. For each user, compute effective role set via BFS (see Section 3).
2. For each SoD constraint `(role1, role2)`: check if both are in the user's effective role set.
3. If yes → SoD conflict; record whether it was direct or via inheritance.

**Complexity:** O(U · (R + E) + U · C) where C = SoD constraints.

---

### 5.4 Redundant Permission

**Algorithm:** For each role R:
1. Compute inherited permission set = union of effective permissions of all parent roles (BFS).
2. If any permission in `R.permissions` is also in the inherited set → redundant warning.

**Complexity:** O(R · (R + E)).

---

### 5.5 Privilege Escalation

**Algorithm:**
1. Build transitive closure of the role graph (which roles are reachable from each role via `inherits`).
2. For each role pair `(A, B)` where B is reachable from A: compute `gained = effective_perms(B) - direct_perms(A)`. If gained is non-empty → escalation path.

**Complexity:** O(R² · (R + E)).

---

### 5.6 Dangerous Permission Combination

**Algorithm:**
1. Define a hardcoded set of dangerous pairs, e.g. `{("execute_trades", "approve_trades"), ("write_data", "delete_data"), ...}`.
2. For each user and each role: compute effective permission set.
3. If both permissions in a dangerous pair are present → dangerous combo.

---

## 6. Detected Security Issues — Documented Cases

### Case 1: Direct SoD Violation
**Policy:** `examples/conflict_policy.rbac`  
**User:** `alice`  
**Roles held:** `Accountant`, `Trader`  
**Constraint violated:** `conflict Accountant and Trader;`  
**Risk:** alice can both create and approve financial transactions — enabling fraud.

---

### Case 2: Inherited SoD Violation
**Policy:** `examples/policy_week7.rbac`  
**User:** `dave`  
**Roles held:** `SeniorAccountant` (which inherits `Accountant`), `Trader`  
**Constraint violated:** `conflict Accountant and Trader;`  
**Risk:** dave does not explicitly hold `Accountant`, but inherits it — the constraint is still violated via the inheritance chain.

---

### Case 3: Unknown Role Reference
**Policy:** `examples/conflict_policy.rbac`  
**User:** `charlie`  
**Assigned role:** `unknown_role`  
**Issue:** `unknown_role` was never declared in the policy.  
**Risk:** Misconfiguration — `charlie` has no defined access, but the policy implies they have some role.

---

### Case 4: Redundant Permission
**Policy:** `examples/conflict_policy.rbac`  
**Role:** `Auditor` (inherits `Accountant`)  
**Permission:** `read_financials` declared in both `Accountant` and explicitly in `Auditor`.  
**Risk:** Policy bloat and confusion — changes to `Accountant`'s permissions may not be reflected correctly.

---

### Case 5: Multi-hop Privilege Escalation
**Policy:** `examples/policy_week8.rbac`  
**Path:** `Intern → Developer → Lead → Admin → SuperAdmin`  
**Permissions gained:** `read_data → write_data → approve_data → delete_data → admin_users`  
**Risk:** A compromised `Intern` account can escalate to full `SuperAdmin` permissions through a 4-hop inheritance chain without any legitimate promotion.

---

### Case 6: Dangerous Permission Combination
**Policy:** `examples/policy_week8.rbac`  
**User/Role:** `eve`  
**Permissions:** `execute_trades + approve_trades`  
**Risk:** Violates the four-eyes principle — one person can both initiate and approve a trade.

---

## 7. API Reference

### Using the Compiler as a Library

```python
import sys, os
sys.path.insert(0, "src")

from rbac_compiler import RBACCompiler

source = open("examples/policy_week9_integration.rbac").read()
compiler = RBACCompiler()
result = compiler.compile(source)

print("Parse OK:", result.parse_ok)
print("Total issues:", result.total_issues)
print("Conflicts:", result.conflict_report.conflicts)
print("Escalation paths:", result.escalation_report.escalation_paths)
```

### Using the Conflict Detector Standalone

```python
from parser import parser
from conflict_detector import ConflictDetector

ast = parser.parse(source)
detector = ConflictDetector()
report = detector.analyse(ast)

for conflict in report.conflicts:
    print(conflict)
```

### Using the Report Generator

```python
from rbac_compiler import RBACCompiler
from report_generator import generate_report

result = RBACCompiler().compile(source)
md = generate_report(result, policy_path="examples/policy.rbac")
print(md)
```

---

## 8. Configuration & Extension Points

### Adding a New Dangerous Permission Pair

In `src/escalation_detector.py`, locate the `DANGEROUS_COMBINATIONS` list and add a new tuple:

```python
DANGEROUS_COMBINATIONS = [
    ("execute_trades", "approve_trades"),
    ("make_payment",   "approve_payment"),
    # Add new pairs here:
    ("create_user",    "delete_user"),
]
```

### Adding a New Token to the Lexer

1. Add the token name to the `tokens` tuple in `src/lexer.py`.
2. Add a `t_TOKENNAME` function or string pattern.
3. If it is a keyword, add it to the `reserved` dictionary.
4. Add grammar rules in `src/parser.py` that use the new token.

### Adding a New AST Node

1. Add a new `@dataclass` class in `src/ast_nodes.py` inheriting from `Node`.
2. Add a grammar rule in `src/parser.py` that creates the new node.
3. Add handling in `conflict_detector.py` Pass 1 and/or Pass 2 as needed.

---

*Technical Documentation — RBAC Policy DSL Compiler | Week 12 | Compiler Design Lab*
