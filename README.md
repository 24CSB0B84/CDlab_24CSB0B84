# CDlab_24CSB0B84
Project Name: 40.RBAC Policy DSL compiler
# RBAC Policy DSL Compiler

> **Compiler Design Lab Project | Weeks 1–11**  
> Language: Python 3.10+ | Parser Toolkit: PLY (Python Lex-Yacc)

A full compiler pipeline for a custom Domain Specific Language (DSL) that parses, validates, and performs security analysis on Role-Based Access Control (RBAC) policies. Detects **Separation of Duty (SoD) conflicts**, **privilege escalation paths**, **redundant permissions**, and **unknown role references** automatically.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Project Structure](#project-structure)
4. [DSL Syntax](#dsl-syntax)
5. [Compiler Pipeline](#compiler-pipeline)
6. [Installation](#installation)
7. [Usage](#usage)
8. [Running Tests](#running-tests)
9. [Example Output](#example-output)
10. [Weekly Progress Summary](#weekly-progress-summary)

---

## Project Overview

In large organisations, RBAC policies can silently accumulate security flaws as they grow. This project builds a **compiler** for a custom `.rbac` policy language that:

- **Lexes** raw policy text into tokens
- **Parses** tokens against a formal grammar into an Abstract Syntax Tree (AST)
- **Analyzes** the AST semantically using a Symbol Table
- **Detects** SoD conflicts, cyclic inheritance, redundant permissions, and unknown references
- **Traces** privilege escalation paths through role inheritance chains

---

## Features

| Feature | Description |
|---|---|
| **Custom DSL (`.rbac`)** | Human-readable syntax for defining roles, permissions, users, and SoD constraints |
| **LALR(1) Parser** | Built with PLY (ply.lex + ply.yacc) |
| **Symbol Table** | Tracks all declared roles, permissions, and users |
| **SoD Conflict Detection** | Finds users holding two mutually exclusive roles (directly or via inheritance) |
| **Cyclic Inheritance Detection** | Uses DFS to find role inheritance loops |
| **Unknown Reference Detection** | Catches references to undeclared roles |
| **Redundant Permission Detection** | Warns when a role re-declares an inherited permission |
| **Privilege Escalation Detection** | Traces escalation paths through the role hierarchy graph |
| **Dangerous Combo Detection** | Identifies high-risk permission combinations across role chains |
| **Evaluation Module** | Measures detected conflicts, false positives, and analysis time |

---

## Project Structure

```
cd_final/
│
├── src/                              ← All source code
│   ├── lexer.py                      ← Week 5: Tokenizer (PLY lex)
│   ├── ast_nodes.py                  ← Week 6: AST node dataclasses
│   ├── parser.py                     ← Week 6: LALR(1) parser (PLY yacc)
│   ├── symbol_table.py               ← Week 7: Symbol table registry
│   ├── semantic_analyzer.py          ← Week 7: Semantic pass (AST walker)
│   ├── conflict_detector.py          ← Week 7: SoD / redundancy / cycle detection
│   ├── escalation_detector.py        ← Week 8: Privilege escalation detection
│   ├── rbac_compiler.py              ← Week 9: Integrated compiler pipeline
│   ├── report_generator.py           ← Week 11: Markdown report generator
│   ├── evaluate.py                   ← Week 10: Evaluation & metrics
│   ├── generate_graphs.py            ← Week 10: Performance graph generation
│   ├── verify_conflicts.py           ← CLI runner for conflict detection
│   ├── verify_escalation.py          ← CLI runner for escalation detection
│   ├── test_lexer.py                 ← Unit test: lexer
│   ├── test_parser.py                ← Unit test: parser
│   ├── test_semantic.py              ← Unit tests: semantic analyzer
│   ├── test_conflict_detector.py     ← 18 unit tests: conflict detector
│   ├── test_escalation_detector.py   ← 16 unit tests: escalation detector
│   └── test_integration.py           ← Week 9: End-to-end integration tests
│
├── examples/                         ← Sample .rbac policy files
│   ├── policy1.rbac                  ← Simple 3-role hierarchy
│   ├── conflict_policy.rbac          ← Classic SoD conflict example
│   ├── policy_week7.rbac             ← Advanced conflict test cases
│   ├── policy_week8.rbac             ← Escalation test policy
│   ├── policy_week9_integration.rbac ← All-issues integration test
│   ├── policy_eval_bank.rbac         ← Bank domain evaluation policy
│   ├── policy_eval_hospital.rbac     ← Hospital domain evaluation policy
│   ├── policy_eval_ecommerce.rbac    ← E-commerce domain evaluation policy
│   └── policy_eval_clean.rbac        ← Clean policy (no issues)
│
│
├── requirements.txt                  ← pip install ply
└── README.md                         ← This file
```

---

## DSL Syntax

The custom `.rbac` language lets you declaratively define an RBAC policy:

```rbac
# Declare individual permissions
permission read_data;
permission write_data;
permission delete_data;

# Define roles with optional inheritance and permissions
role Intern {
    permissions read_data;
}

role Developer {
    inherits Intern;
    permissions write_data;
}

role Admin {
    inherits Developer;
    permissions delete_data;
}

# Assign users to roles
user alice engages Developer;
user bob engages Admin;

# Declare Separation of Duty constraints
conflict Accountant and Trader;
```

### Language Keywords

| Keyword | Purpose |
|---|---|
| `permission` | Declare a named permission |
| `role` | Define a role block |
| `inherits` | Specify parent roles inside a role block |
| `permissions` | List permissions granted to a role |
| `user` | Assign a user to roles |
| `engages` | Connects a user to their roles |
| `conflict` | Declare an SoD constraint between two roles |

---

## Compiler Pipeline

```
Policy File (.rbac)
       │
       ▼
  [Phase 1 & 2]  Lexer + Parser  →  Abstract Syntax Tree (AST)
       │
       ▼
  [Phase 3]      Semantic Analyzer  →  Symbol Table validation
       │
       ▼
  [Phase 4]      Conflict Detector  →  SoD, cycles, unknowns, redundancy
       │
       ▼
  [Phase 5]      Escalation Detector  →  Escalation paths, dangerous combos
       │
       ▼
  [Phase 6]      Report Generated
```

---

## Installation

**Prerequisites:** Python 3.10+

```powershell
# Clone or navigate to the project directory

# Install dependencies
pip install -r requirements.txt
```

`requirements.txt` contains:
```
ply
```

---

## Usage

### Run the full compiler on a policy file

```powershell
python src/rbac_compiler.py examples/policy1.rbac
python src/rbac_compiler.py examples/conflict_policy.rbac
python src/rbac_compiler.py examples/policy_week9_integration.rbac
```

### Generate a security report (Markdown)

```powershell
python src/report_generator.py examples/policy_week9_integration.rbac
```

### Run conflict detection only

```powershell
python src/verify_conflicts.py examples/policy_week7.rbac
```

### Run escalation detection only

```powershell
python src/verify_escalation.py examples/policy_week8.rbac
```

### Run evaluation across all policies

```powershell
python src/evaluate.py
```

---

## Running Tests

```powershell
# Individual test suites
python src/test_lexer.py
python src/test_parser.py
python src/test_semantic.py
python src/test_conflict_detector.py
python src/test_escalation_detector.py
python src/test_integration.py
```

---

## Example Output

```
======================================================================
  RBAC Policy DSL Compiler   -   Week 9: Integrated Pipeline
  Policy : examples/conflict_policy.rbac
======================================================================

  ====================================================================
  PHASE 1 & 2 - LEXICAL + SYNTAX ANALYSIS
  ====================================================================
    [OK] Parsed successfully - 8 top-level statements found.

  ====================================================================
  PHASE 4 - CONFLICT DETECTION  (SoD / Redundant / Unknown / Cycles)
  ====================================================================
    [CONFLICT] alice holds both Accountant and Trader (SoD violation!)
    Summary: 0 error(s), 1 SoD conflict(s), 0 warning(s)

  ====================================================================
  COMPILER RESULT
  ====================================================================
    [WARN] POLICY HAS 1 ISSUE(S) - review the report above.
```

---

## Weekly Progress Summary

| Week | Topic | Deliverable |
|---|---|---|
| 1 | Problem Definition | RBAC security flaws identified |
| 2 | Literature Review | Compiler theory & RBAC research |
| 3 | System Design | DSL syntax & compiler architecture |
| 4 | Grammar Design (BNF) | Full formal grammar specification |
| 5 | Lexical Analysis | `lexer.py` — tokenizer with PLY |
| 6 | Syntax Analysis | `parser.py`, `ast_nodes.py` — LALR(1) parser + AST |
| 7 | Semantic Analysis | `symbol_table.py`, `conflict_detector.py` — SoD detection |
| 8 | Privilege Escalation | `escalation_detector.py` — graph-based escalation tracing |
| 9 | Integration | `rbac_compiler.py`, `test_integration.py` — full pipeline |
| 10 | Evaluation | `evaluate.py`, `generate_graphs.py` — metrics & graphs |
| 11 | Report Generation | `report_generator.py` — Markdown + Mermaid.js reports |

---

> **Author:** 24CSB0B84
> **Tools:** Python, PLY (Python Lex-Yacc), Mermaid.js  
> **Language:** Python 3.10+
