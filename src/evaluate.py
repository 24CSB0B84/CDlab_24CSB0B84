"""
evaluate.py  -  Week 10: RBAC Compiler Evaluation Harness
Run: python src/evaluate.py
"""
import os, sys, time, json
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
from rbac_compiler import RBACCompiler

ROOT_DIR    = os.path.dirname(SRC_DIR)
EXAMPLES    = os.path.join(ROOT_DIR, "examples")
REPORTS_DIR = os.path.join(ROOT_DIR, "reports")

# Ground-truth: manually verified expected issue counts per policy
GROUND_TRUTH = {
    "policy_eval_hospital.rbac": {
        "description": "Healthcare system - SoD conflicts and escalation paths",
        "domain": "Healthcare",
        "expected_conflicts": 4,
        "expected_escalation_paths": 3,
        "expected_semantic_errors": 2,
        "expected_warnings": 2,
        "is_clean": False,
    },
    "policy_eval_bank.rbac": {
        "description": "Banking/finance - dangerous permission combos",
        "domain": "Finance",
        "expected_conflicts": 5,
        "expected_escalation_paths": 4,
        "expected_semantic_errors": 2,
        "expected_warnings": 3,
        "is_clean": False,
    },
    "policy_eval_ecommerce.rbac": {
        "description": "E-commerce - complex role hierarchy",
        "domain": "E-Commerce",
        "expected_conflicts": 3,
        "expected_escalation_paths": 2,
        "expected_semantic_errors": 1,
        "expected_warnings": 2,
        "is_clean": False,
    },
    "policy_eval_clean.rbac": {
        "description": "Clean policy - zero violations (false-positive benchmark)",
        "domain": "Education",
        "expected_conflicts": 0,
        "expected_escalation_paths": 0,
        "expected_semantic_errors": 0,
        "expected_warnings": 0,
        "is_clean": True,
    },
}

def _count_conflicts(cr):
    if cr is None:
        return 0
    return len(getattr(cr, "conflicts", []))

def _count_escalations(er):
    if er is None:
        return 0
    paths = getattr(er, "escalation_paths", None)
    if paths is None:
        paths = getattr(er, "paths", [])
    return len(paths)

def _count_errors(result):
    errs = getattr(result, "semantic_errors", [])
    return len([e for e in errs if isinstance(e, str) and "error" in e.lower()])

def _count_warnings(result):
    w = len(getattr(result, "warnings", []))
    cr = result.conflict_report
    if cr:
        w += len(getattr(cr, "warnings", []))
    return w

def _false_positives(name, d_conf, d_esc, d_err):
    gt = GROUND_TRUTH.get(name, {})
    if gt.get("is_clean", False):
        return d_conf + d_esc + d_err
    fp  = max(0, d_conf - gt.get("expected_conflicts",        0))
    fp += max(0, d_esc  - gt.get("expected_escalation_paths", 0))
    fp += max(0, d_err  - gt.get("expected_semantic_errors",  0))
    return fp


def evaluate_policy(path, compiler):
    name = os.path.basename(path)
    gt   = GROUND_TRUTH.get(name, {})
    try:
        source = open(path, encoding="utf-8").read()
    except Exception as exc:
        return {"policy": name, "error": str(exc)}

    t0 = time.perf_counter()
    try:
        result = compiler.compile(source)
    except Exception as exc:
        return {"policy": name, "error": str(exc),
                "analysis_time_ms": round((time.perf_counter()-t0)*1000, 2)}
    ms = round((time.perf_counter()-t0)*1000, 2)

    d_conf = _count_conflicts(result.conflict_report)
    d_esc  = _count_escalations(result.escalation_report)
    d_err  = _count_errors(result)
    d_warn = _count_warnings(result)
    fp     = _false_positives(name, d_conf, d_esc, d_err)
    tp     = (d_conf + d_esc + d_err) - fp

    exp_total = (gt.get("expected_conflicts",        0)
               + gt.get("expected_escalation_paths", 0)
               + gt.get("expected_semantic_errors",  0))
    det_total  = d_conf + d_esc + d_err
    precision  = round(tp / det_total * 100 if det_total > 0 else 100.0, 1)
    recall     = round(tp / exp_total  * 100 if exp_total > 0 else 100.0, 1)
    fp_rate    = round(fp / max(1, det_total) * 100, 1)

    return {
        "policy":                    name,
        "domain":                    gt.get("domain", ""),
        "description":               gt.get("description", ""),
        "analysis_time_ms":          ms,
        "detected_conflicts":        d_conf,
        "detected_escalation_paths": d_esc,
        "detected_semantic_errors":  d_err,
        "detected_warnings":         d_warn,
        "expected_conflicts":        gt.get("expected_conflicts",        0),
        "expected_escalation_paths": gt.get("expected_escalation_paths", 0),
        "expected_semantic_errors":  gt.get("expected_semantic_errors",  0),
        "true_positives":            tp,
        "false_positives":           fp,
        "precision_pct":             precision,
        "recall_pct":                recall,
        "false_positive_rate_pct":   fp_rate,
    }


def print_summary(results):
    SEP = "-" * 92
    print()
    print("=" * 92)
    print("  RBAC COMPILER  -  WEEK 10 EVALUATION RESULTS")
    print("=" * 92)
    print(f"  {'Policy':<32} {'Time(ms)':>9} {'Conf':>6} {'Esc':>5} {'Err':>5} {'FP':>5} {'Prec%':>7} {'Rec%':>6}")
    print(SEP)
    for r in results:
        if "error" in r:
            print(f"  {r['policy']:<32}  ERROR: {r['error']}")
            continue
        print(
            f"  {r['policy']:<32}"
            f"  {r['analysis_time_ms']:>9.1f}"
            f"  {r['detected_conflicts']:>6}"
            f"  {r['detected_escalation_paths']:>5}"
            f"  {r['detected_semantic_errors']:>5}"
            f"  {r['false_positives']:>5}"
            f"  {r['precision_pct']:>6.1f}%"
            f"  {r['recall_pct']:>5.1f}%"
        )
    print(SEP)
    ok = [r for r in results if "error" not in r]
    if ok:
        print(f"  Policies evaluated     : {len(ok)}")
        print(f"  Avg analysis time      : {sum(r['analysis_time_ms'] for r in ok)/len(ok):.1f} ms")
        print(f"  Total conflicts        : {sum(r['detected_conflicts'] for r in ok)}")
        print(f"  Total escalation paths : {sum(r['detected_escalation_paths'] for r in ok)}")
        print(f"  Total false positives  : {sum(r['false_positives'] for r in ok)}")
        print(f"  Avg precision          : {sum(r['precision_pct'] for r in ok)/len(ok):.1f}%")
        print(f"  Avg recall             : {sum(r['recall_pct'] for r in ok)/len(ok):.1f}%")
    print("=" * 92 + "\n")


def main():
    compiler = RBACCompiler()
    results  = []

    print(f"\nEvaluating {len(GROUND_TRUTH)} RBAC policies ...\n")
    for fname in sorted(GROUND_TRUTH.keys()):
        fpath = os.path.join(EXAMPLES, fname)
        if not os.path.exists(fpath):
            print(f"  [SKIP] {fname}  -  file not found")
            results.append({"policy": fname, "error": "file not found"})
            continue
        print(f"  Analysing {fname} ...", end=" ", flush=True)
        m = evaluate_policy(fpath, compiler)
        results.append(m)
        if "error" in m:
            print(f"ERROR - {m['error']}")
        else:
            print(
                f"OK  ({m['analysis_time_ms']:.1f} ms, "
                f"conf={m['detected_conflicts']}, "
                f"esc={m['detected_escalation_paths']}, "
                f"FP={m['false_positives']})"
            )

    print_summary(results)

    out = os.path.join(REPORTS_DIR, "evaluation_results.json")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"results": results}, f, indent=2)
    print(f"Results saved  ->  {out}\n")
    return results


if __name__ == "__main__":
    main()
