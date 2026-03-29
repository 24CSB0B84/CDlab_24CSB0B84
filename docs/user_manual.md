# RBAC Policy DSL Compiler — User Manual

> **Week 12 Deliverable | Compiler Design Lab**  
> A practical guide for writing RBAC policies and using the compiler

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Quick Start — Your First Policy](#3-quick-start--your-first-policy)
4. [Writing RBAC Policies](#4-writing-rbac-policies)
5. [Running the Compiler](#5-running-the-compiler)
6. [Understanding the Output](#6-understanding-the-output)
7. [Generating Security Reports](#7-generating-security-reports)
8. [Running Evaluations](#8-running-evaluations)
9. [Troubleshooting](#9-troubleshooting)
10. [Complete Worked Example](#10-complete-worked-example)

---

## 1. Introduction

The **RBAC Policy DSL Compiler** lets you:

1. **Write** an RBAC policy in a simple text file (`.rbac` extension)
2. **Compile** the policy to detect syntax and semantic errors
3. **Analyse** the policy for security flaws automatically

You do not need to be a programmer to write policy files. The language is designed to read like plain English sentences.

### What the Compiler Checks For

| Issue | What It Means | Severity |
|---|---|---|
| **Syntax error** | Your policy file has a typo or formatting mistake | ❌ Fatal |
| **Unknown role reference** | You assigned a user to a role that doesn't exist | ❌ Error |
| **Duplicate declaration** | You declared the same role or user twice | ❌ Error |
| **Cyclic inheritance** | Role A inherits B, and B inherits A — impossible loop | ❌ Error |
| **SoD conflict** | A user holds two mutually exclusive roles | ⚡ Conflict |
| **Redundant permission** | A role declares a permission it already inherits | ⚠ Warning |
| **Privilege escalation** | A low-privilege role can reach high-privilege permissions | ⬆ Escalation |
| **Dangerous combo** | A user/role holds two high-risk permissions together | ⚠ Dangerous |

---

## 2. Installation

### Step 1 — Verify Python Version

Open a terminal (PowerShell on Windows) and run:

```powershell
python --version
```

You need **Python 3.10 or later**. If Python is not installed, download it from [python.org](https://python.org).

### Step 2 — Navigate to the Project

```powershell
cd path\to\cd_week6_final
```

### Step 3 — Install Dependencies

```powershell
pip install -r requirements.txt
```

This installs `ply` (Python Lex-Yacc), the only dependency.

### Step 4 — Verify Installation

```powershell
python src/rbac_compiler.py examples/policy1.rbac
```

You should see output ending with:
```
[OK] CLEAN POLICY - no security issues detected.
```

---

## 3. Quick Start — Your First Policy

### Step 1 — Create a Policy File

Create a new file called `my_policy.rbac` in the `examples/` folder:

```
# My first RBAC policy

permission read_reports;
permission edit_records;
permission delete_records;

role Viewer {
    permissions read_reports;
}

role Editor {
    inherits Viewer;
    permissions edit_records;
}

role Admin {
    inherits Editor;
    permissions delete_records;
}

user alice engages Editor;
user bob   engages Admin;
user carol engages Viewer;
```

### Step 2 — Run the Compiler

```powershell
python src/rbac_compiler.py examples/my_policy.rbac
```

### Step 3 — Read the Output

For a clean policy, you will see:
```
[OK] CLEAN POLICY - no security issues detected.
```

### Step 4 — Introduce a Conflict (Optional Demo)

Add these two lines to your policy file:

```
conflict Viewer and Admin;
user dave engages Viewer, Admin;
```

Run the compiler again. You should now see:
```
[CONFLICT] User 'dave' violates SoD: holds conflicting roles 'Viewer' and 'Admin'
[WARN] POLICY HAS 1 ISSUE(S) - review the report above.
```

---

## 4. Writing RBAC Policies

### 4.1 Declaring Permissions

Every access right in your system needs to be declared before it can be used:

```
permission <name>;
```

**Guidelines:**
- Use descriptive, lowercase names with underscores: `read_patient_records`, `approve_payment`
- Declare all permissions at the top of the file for clarity
- Each permission name must be unique

```
permission read_data;
permission write_data;
permission delete_data;
permission approve_payment;
permission make_payment;
```

---

### 4.2 Defining Roles

A role groups related permissions and can inherit from other roles:

```
role <RoleName> {
    inherits <Parent1>, <Parent2>;    # optional
    permissions <perm1>, <perm2>;     # optional
}
```

**Guidelines:**
- Use descriptive names: `SeniorAccountant`, `ReadOnlyAnalyst`
- Use inheritance (`inherits`) to build role hierarchies — avoid copy-pasting permissions
- Keep role bodies focused — a role should represent one job function

```
role Intern {
    permissions read_data;
}

role Developer {
    inherits Intern;          # Developer gets read_data for free
    permissions write_data;   # plus write_data
}

role Admin {
    inherits Developer;       # Admin gets read + write for free
    permissions delete_data;  # plus delete_data
}
```

---

### 4.3 Assigning Users

A user statement assigns a person to one or more roles:

```
user <username> engages <role1>, <role2>;
```

**Guidelines:**
- One `user` statement per person
- Only assign roles that serve the person's actual job function
- Avoid assigning multiple high-privilege roles to one user

```
user alice  engages Developer;
user bob    engages Intern;
user carol  engages Admin;
```

---

### 4.4 Declaring SoD Constraints

A conflict statement says: "no user should ever hold both of these roles at the same time":

```
conflict <Role1> and <Role2>;
```

**When to use conflict constraints:**
- Maker-checker patterns: the person who *creates* a payment should not also *approve* it
- Audit independence: the auditor should not also be able to modify records
- Access separation: read-only roles should not coexist with delete roles in sensitive areas

```
conflict Accountant and Trader;
conflict Maker       and Checker;
conflict Intern      and Admin;
```

---

### 4.5 Using Comments

Use `#` for comments to explain your policy:

```
# =====================
# Finance Department
# =====================
permission read_financials;
permission write_financials;

role Accountant {
    # Accountants can read and write financial records
    permissions read_financials, write_financials;
}
```

---

## 5. Running the Compiler

### Command Reference

| Command | What It Does |
|---|---|
| `python src/rbac_compiler.py <file>` | Full compiler pipeline (all phases) |
| `python src/verify_conflicts.py <file>` | Conflict detection only (SoD, unknown refs, cycles) |
| `python src/verify_escalation.py <file>` | Escalation detection only |
| `python src/report_generator.py <file>` | Generate Markdown security report |
| `python src/evaluate.py` | Run evaluation on all benchmark policies |

### Example Commands

```powershell
# Analyse a specific policy
python src/rbac_compiler.py examples/policy_week9_integration.rbac

# Check only for conflicts
python src/verify_conflicts.py examples/my_policy.rbac

# Check only for escalation
python src/verify_escalation.py examples/policy_week8.rbac

# Generate a readable Markdown report
python src/report_generator.py examples/my_policy.rbac
```

---

## 6. Understanding the Output

### 6.1 Phase Banners

The full compiler prints a banner for each phase:

```
======================================================================
  PHASE 1 & 2 - LEXICAL + SYNTAX ANALYSIS
======================================================================
    [OK] Parsed successfully - 12 top-level statements found.
```

If parsing fails:
```
    [FAIL] Parsing FAILED - aborting compilation.
```

---

### 6.2 Conflict Detection Output

```
======================================================================
  PHASE 4 - CONFLICT DETECTION  (SoD / Redundant / Unknown / Cycles)
======================================================================

  [ERRORS]
    ✗ User 'charlie' assigned to unknown role 'ghost_role'

  [SoD CONFLICTS]
    ⚡ User 'alice' violates SoD: holds conflicting roles 'Accountant'
       and 'Trader' (direct assignment)
    ⚡ User 'dave' violates SoD: holds conflicting roles 'Accountant'
       and 'Trader' (via role inheritance from 'SeniorAccountant')

  [WARNINGS]
    ⚠ Role 'Auditor' has redundant permission 'read_financials'
      (already inherited from 'Accountant')

  Summary: 1 error(s), 2 SoD conflict(s), 1 warning(s)  [4 issues total]
```

**Reading the symbols:**
- `✗` / `[ERRORS]` — must fix; policy is misconfigured
- `⚡` / `[SoD CONFLICTS]` — security violation; must investigate
- `⚠` / `[WARNINGS]` — non-fatal; worth cleaning up

---

### 6.3 Escalation Detection Output

```
======================================================================
  PHASE 5 - PRIVILEGE ESCALATION DETECTION
======================================================================

  [ROLE HIERARCHY GRAPH]
    Developer   ──inherits──▶  Intern
    Admin       ──inherits──▶  Developer

  [PRIVILEGE ESCALATION PATHS]  (2 found)
    ↑ Developer → Intern   [gains: read_data]
    ↑ Admin     → Developer [gains: write_data]

  [DANGEROUS PERMISSION COMBINATIONS]  (1 found)
    ⚠ User 'eve' holds dangerous combination: 'execute_trades' + 'approve_trades'

  Summary: 2 escalation path(s), 1 dangerous combo(s)  [3 issues total]
```

---

### 6.4 Final Verdict

```
======================================================================
  COMPILER RESULT
======================================================================
    [OK]   CLEAN POLICY - no security issues detected.
    -- or --
    [WARN] POLICY HAS 5 ISSUE(S) - review the report above.
```

---

## 7. Generating Security Reports

To get a nicely formatted Markdown report instead of terminal output:

```powershell
python src/report_generator.py examples/policy_week9_integration.rbac
```

The report includes:
- **Summary table** of all issues by category
- **Mermaid.js role hierarchy diagram** — paste it into a Markdown viewer to see a visual graph
- **Detailed SoD conflict list**
- **Detailed escalation path table**
- **Warnings list**

To save the report to a file, redirect the output:

```powershell
python src/report_generator.py examples/my_policy.rbac > reports/my_report.md
```

---

## 8. Running Evaluations

The evaluation module benchmarks the compiler against realistic domain policies:

```powershell
python src/evaluate.py
```

This runs the compiler on:
- `examples/policy_eval_bank.rbac` — Banking domain
- `examples/policy_eval_hospital.rbac` — Hospital domain
- `examples/policy_eval_ecommerce.rbac` — E-commerce domain
- `examples/policy_eval_clean.rbac` — Baseline clean policy

**Output:** Results are saved to `reports/evaluation_results.json`.

To generate performance graphs:

```powershell
python src/generate_graphs.py
```

Graphs are saved to `reports/graphs/`.

---

## 9. Troubleshooting

### "Syntax error at '<token>'"

Your policy file has a formatting mistake near the token shown.

**Common causes:**
- Missing semicolon `;` at the end of a statement
- Missing closing brace `}` on a role block
- Typo in a keyword (e.g. `permisison` instead of `permission`)

**Fix:** Check the line number shown in the error message and verify the syntax against [Section 4](#4-writing-rbac-policies).

---

### "Syntax error at EOF"

The file ends before a statement is closed.

**Common cause:** Missing `;` on the last line or missing `}` closing a role block.

---

### "User '<u>' assigned to unknown role '<r>'"

A `user ... engages ...` statement references a role that was never declared with `role`.

**Fix:** Either add `role <r> { }` to your policy or correct the role name spelling.

---

### "Role '<A>' inherits from unknown role '<B>'"

A role's `inherits` clause references a role that was never declared.

**Fix:** Ensure `role <B> { }` exists in your policy file.

---

### "Cyclic inheritance: '<A>' -> '<B>'"

Two roles inherit each other, creating an infinite loop.

**Fix:** Review your inheritance chain and remove the circular reference.

---

### PLY Warning: "Token 'X' defined, but not used"

This is a harmless PLY internal warning. It does not affect compilation results.

---

### Output appears garbled (Unicode symbols broken)

On Windows PowerShell, run:

```powershell
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001
```

Then retry the compiler command.

---

## 10. Complete Worked Example

This section walks through a realistic scenario from policy creation to security report.

### Scenario

You are a system administrator for a hospital. You want to model access control for:
- Doctors
- Nurses
- Receptionists
- Billing staff
- IT administrators

### Step 1 — Create `examples/hospital.rbac`

```
# Hospital Access Control Policy

# ── Permissions ──
permission view_patient_records;
permission edit_patient_records;
permission prescribe_medication;
permission view_billing;
permission edit_billing;
permission view_appointments;
permission edit_appointments;
permission admin_system;
permission audit_logs;

# ── Roles ──
role Receptionist {
    permissions view_appointments, edit_appointments;
}

role Nurse {
    inherits Receptionist;
    permissions view_patient_records;
}

role Doctor {
    inherits Nurse;
    permissions edit_patient_records, prescribe_medication;
}

role BillingStaff {
    permissions view_billing, edit_billing;
}

role ITAdmin {
    permissions admin_system;
}

role Auditor {
    permissions audit_logs, view_patient_records, view_billing;
}

# ── Users ──
user dr_smith    engages Doctor;
user nurse_jones engages Nurse;
user mary_rec    engages Receptionist;
user john_bill   engages BillingStaff;
user IT_alice    engages ITAdmin;
user auditor_bob engages Auditor;

# ── SoD Constraints ──
conflict BillingStaff and Doctor;    # doctors should not edit billing
conflict ITAdmin       and Auditor;  # IT admin should not audit themselves
conflict BillingStaff  and Auditor;  # billing should not self-audit
```

### Step 2 — Run the Compiler

```powershell
python src/rbac_compiler.py examples/hospital.rbac
```

### Step 3 — Read the Output

Expected output for this clean policy:
```
  [OK] Parsed successfully - 23 top-level statements found.
  [OK] No semantic errors found.
  Summary: 0 error(s), 0 SoD conflict(s), 0 warning(s)  [0 issues total]
  Summary: 0 escalation path(s), 0 dangerous combo(s)   [0 issues total]
  [OK] CLEAN POLICY - no security issues detected.
```

### Step 4 — Test a Violation

Add a problematic user to the policy:

```
user dr_evil engages Doctor, BillingStaff;
```

Run again:
```
[CONFLICT] User 'dr_evil' violates SoD: holds conflicting roles 'BillingStaff' and 'Doctor'
[WARN] POLICY HAS 1 ISSUE(S) - review the report above.
```

### Step 5 — Generate a Security Report

```powershell
python src/report_generator.py examples/hospital.rbac > reports/hospital_security.md
```

Open `reports/hospital_security.md` to view a full formatted report with role hierarchy diagram.

---

*User Manual — RBAC Policy DSL Compiler | Week 12 | Compiler Design Lab*
