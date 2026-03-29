# RBAC Policy DSL — Language Reference

> **Week 12 Deliverable | Compiler Design Lab**  
> The complete specification of the `.rbac` Domain Specific Language

---

## Table of Contents

1. [Language Overview](#1-language-overview)
2. [File Format](#2-file-format)
3. [Lexical Rules](#3-lexical-rules)
4. [Complete Grammar (BNF)](#4-complete-grammar-bnf)
5. [Statements Reference](#5-statements-reference)
6. [Examples](#6-examples)
7. [Error Reference](#7-error-reference)

---

## 1. Language Overview

The RBAC DSL (`.rbac`) is a human-readable, declarative language for defining Role-Based Access Control policies. A policy file specifies:

- **Permissions** — atomic access rights
- **Roles** — named groups of permissions that can inherit from other roles
- **Users** — principals assigned to one or more roles
- **Conflict constraints** — Separation of Duty rules preventing role co-assignment

The language is:
- **Declarative** — order of statements does not affect semantics (declarations are resolved after full parsing)
- **Case-sensitive** — `Admin` and `admin` are different identifiers
- **Whitespace-insensitive** — spaces, tabs, and newlines are ignored (except inside strings)
- **Comment-supporting** — line comments starting with `#`

---

## 2. File Format

| Property | Value |
|---|---|
| File extension | `.rbac` |
| Encoding | UTF-8 |
| Line endings | LF or CRLF |
| Comments | Lines starting with `#` |

---

## 3. Lexical Rules

### 3.1 Identifiers

An identifier starts with a letter or underscore, followed by any combination of letters, digits, and underscores:

```
identifier ::= [a-zA-Z_][a-zA-Z0-9_]*
```

**Valid identifiers:** `alice`, `read_data`, `Admin`, `SeniorAccountant`, `role2`  
**Invalid identifiers:** `2role`, `read-data`, `role name`

### 3.2 Reserved Keywords

The following words are reserved and cannot be used as identifiers:

| Keyword | Token | Purpose |
|---|---|---|
| `role` | `ROLE` | Begin a role definition |
| `permission` | `PERMISSION` | Declare a permission |
| `user` | `USER` | Assign a user to roles |
| `conflict` | `CONFLICT` | Declare an SoD constraint |
| `inherits` | `INHERITS` | Specify parent roles |
| `permissions` | `PERMISSIONS` | List permissions in a role block |
| `engages` | `ENGAGES` | Connect user to roles |
| `and` | `AND` | Separator in conflict declarations |

### 3.3 Punctuation

| Symbol | Token | Usage |
|---|---|---|
| `{` | `LBRACE` | Open a role body |
| `}` | `RBRACE` | Close a role body |
| `;` | `SEMI` | Terminate a statement |
| `,` | `COMMA` | Separate items in a list |

### 3.4 Comments

Comments begin with `#` and extend to the end of the line. They are completely ignored by the compiler.

```rbac
# This is a full-line comment
permission read_data;  # This is an inline comment
```

---

## 4. Complete Grammar (BNF)

```
policy         ::= statement_list

statement_list ::= statement statement_list
                 | statement

statement      ::= role_def
                 | perm_def
                 | user_def
                 | sod_def

perm_def       ::= 'permission' IDENTIFIER ';'

role_def       ::= 'role' IDENTIFIER '{' role_body '}'

role_body      ::= role_attr role_body
                 | ε

role_attr      ::= 'inherits'    id_list ';'
                 | 'permissions' id_list ';'

user_def       ::= 'user' IDENTIFIER 'engages' id_list ';'

sod_def        ::= 'conflict' IDENTIFIER 'and' IDENTIFIER ';'

id_list        ::= IDENTIFIER ',' id_list
                 | IDENTIFIER
```

**Notation:**
- `::=` — "is defined as"
- `|` — alternative (OR)
- `ε` — empty (nothing)
- `'keyword'` — literal reserved word (terminal)
- `IDENTIFIER` — token matching `[a-zA-Z_][a-zA-Z0-9_]*` that is not a keyword

---

## 5. Statements Reference

### 5.1 `permission` — Permission Declaration

**Syntax:**
```
permission <name> ;
```

**Semantics:** Declares a named permission that can be assigned to roles.

**Constraints:**
- `<name>` must be a valid identifier
- Each permission name must be unique within the policy
- A permission must be declared before it can be assigned to a role (semantic check)

**Example:**
```rbac
permission read_data;
permission write_data;
permission delete_data;
```

**Errors:**
- Duplicate permission name → `ERROR: Duplicate permission: '<name>'`

---

### 5.2 `role` — Role Definition

**Syntax:**
```
role <name> {
    [ inherits  <parent1> [, <parent2>, ...] ; ]
    [ permissions <perm1> [, <perm2>, ...] ; ]
}
```

**Semantics:** Defines a role. A role may optionally:
- **Inherit** from one or more parent roles (gaining all their permissions transitively)
- **Declare** additional direct permissions

Both `inherits` and `permissions` clauses are optional. The body may be empty `{}`.

**Multiple `inherits` and `permissions` clauses** are allowed within one role block.

**Constraints:**
- `<name>` must be a valid identifier
- Each role name must be unique within the policy
- All names in `inherits` must reference declared roles (checked semantically)
- All names in `permissions` must reference declared permissions (checked semantically)
- The inheritance graph must be acyclic (DFS check)

**Examples:**
```rbac
# Minimal role — no permissions, no inheritance
role Guest {}

# Role with direct permissions
role Intern {
    permissions read_data;
}

# Role with single parent inheritance
role Developer {
    inherits Intern;
    permissions write_data;
}

# Role with multiple parents
role TechLead {
    inherits Developer, Analyst;
    permissions approve_code;
}

# Role with multiple permissions
role Admin {
    inherits Developer;
    permissions delete_data, admin_users, audit_log;
}
```

**Errors:**
- Duplicate role name → `ERROR: Duplicate role: '<name>'`
- Inherits from unknown role → `ERROR: Role '<name>' inherits from unknown role '<parent>'`
- Cyclic inheritance → `ERROR: Cyclic inheritance: '<A>' -> '<B>'`
- Redundant permission (already inherited) → `WARNING: Role '<name>' has redundant permission '<perm>'`

---

### 5.3 `user` — User Assignment

**Syntax:**
```
user <username> engages <role1> [, <role2>, ...] ;
```

**Semantics:** Assigns a user to one or more roles. The user's **effective role set** includes all listed roles plus all roles reachable through inheritance chains.

**Constraints:**
- `<username>` must be a valid identifier
- Each username must be unique within the policy
- All roles listed must be declared in the policy

**Examples:**
```rbac
# Single role assignment
user alice engages Developer;

# Multiple role assignment
user bob engages Intern, Analyst;

# Admin user
user charlie engages Admin;
```

**Errors:**
- Duplicate user → `ERROR: Duplicate user: '<name>'`
- Unknown role assigned → `ERROR: User '<name>' assigned to unknown role '<role>'`
- SoD constraint violated → `CONFLICT: User '<name>' holds both '<role1>' and '<role2>'`

---

### 5.4 `conflict` — Separation of Duty Constraint

**Syntax:**
```
conflict <role1> and <role2> ;
```

**Semantics:** Declares that no user may simultaneously hold both `<role1>` and `<role2>` (directly or via inheritance). When a user's effective role set contains both roles, a SoD conflict is reported.

**Constraints:**
- Both `<role1>` and `<role2>` should be declared roles
- Multiple conflict constraints can coexist in one policy
- Constraints are symmetric: `conflict A and B` is equivalent to `conflict B and A`

**Examples:**
```rbac
# Classic financial SoD: maker-checker principle
conflict Accountant and Trader;

# Separation between privileged roles
conflict Admin and Auditor;

# Intern should not gain developer access
conflict Intern and Developer;
```

---

## 6. Examples

### 6.1 Minimal Valid Policy

```rbac
permission read_data;
role Viewer { permissions read_data; }
user guest engages Viewer;
```

### 6.2 Multi-level Role Hierarchy

```rbac
permission read_data;
permission write_data;
permission approve_data;
permission delete_data;

role Intern {
    permissions read_data;
}

role Developer {
    inherits Intern;
    permissions write_data;
}

role Lead {
    inherits Developer;
    permissions approve_data;
}

role Admin {
    inherits Lead;
    permissions delete_data;
}

user alice engages Developer;
user bob   engages Lead;
user carol engages Admin;
```

### 6.3 Policy with SoD Constraints

```rbac
permission read_financials;
permission write_financials;
permission execute_trades;
permission approve_trades;
permission audit_log;

role Accountant {
    permissions read_financials, write_financials;
}

role Trader {
    permissions execute_trades;
}

role Checker {
    permissions approve_trades;
}

role Auditor {
    inherits Accountant;
    permissions audit_log;
}

user alice  engages Accountant;
user bob    engages Trader, Checker;
user carol  engages Auditor;

# SoD constraints
conflict Accountant and Trader;
conflict Trader      and Checker;
```

**Expected analysis output:**
- `bob` holds both `Trader` and `Checker` → SoD violation (`conflict Trader and Checker`)

### 6.4 Policy with Multiple Issues (Integration Test)

```rbac
permission read_data;
permission write_data;
permission delete_data;
permission admin_users;

role Intern    { permissions read_data; }
role Developer { inherits Intern; permissions write_data; }
role Admin     { inherits Developer; permissions delete_data, admin_users; }

user alice  engages Intern;
user bob    engages Admin;
user charlie engages ghost_role;     # unknown role

conflict Intern and Admin;

user dave engages Intern, Admin;    # direct SoD violation
```

**Expected analysis:**
- `ERROR`: `charlie` assigned to unknown role `ghost_role`
- `CONFLICT`: `dave` holds both `Intern` and `Admin`
- `ESCALATION`: 3 paths (Intern→Developer, Developer→Admin, Intern→Admin transitively)

---

## 7. Error Reference

### Syntax Errors

| Error | Cause | Example |
|---|---|---|
| `Syntax error at '<token>'` | Unexpected token in grammar | `role { }` (missing name) |
| `Syntax error at EOF` | Policy ends mid-statement | `permission read_data` (missing `;`) |

### Semantic Errors

| Error | Cause |
|---|---|
| `Duplicate permission: '<name>'` | Same permission declared twice |
| `Duplicate role: '<name>'` | Same role name defined twice |
| `Duplicate user: '<name>'` | Same username appears twice |
| `Role '<A>' inherits from unknown role '<B>'` | `<B>` was never declared |
| `User '<u>' assigned to unknown role '<r>'` | `<r>` was never declared |
| `Cyclic inheritance: '<A>' -> '<B>'` | Role inheritance forms a loop |

### Conflict Reports

| Report Level | Message | Meaning |
|---|---|---|
| `CONFLICT` | `User '<u>' violates SoD: holds '<r1>' and '<r2>'` | User's effective role set includes both conflicting roles |
| `WARNING` | `Role '<r>' has redundant permission '<p>'` | Permission already inherited from a parent role |

### Escalation Reports

| Report Level | Message | Meaning |
|---|---|---|
| `ESCALATION` | `<A> -> <B> [gains: <perms>]` | Role A can reach Role B's permissions via inheritance |
| `DANGEROUS COMBO` | `'<perm1>' + '<perm2>' held by <entity>` | A dangerous permission combination is present |

---

*DSL Language Reference — RBAC Policy DSL Compiler | Week 12 | Compiler Design Lab*
