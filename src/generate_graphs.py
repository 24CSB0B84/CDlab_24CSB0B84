"""
generate_graphs.py  -  Week 10: Performance Graph Generator
Run: python src/generate_graphs.py
Requires: matplotlib
"""
import os, sys, json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

ROOT_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS    = os.path.join(ROOT_DIR, "reports")
GRAPHS_DIR = os.path.join(REPORTS, "graphs")
JSON_PATH  = os.path.join(REPORTS, "evaluation_results.json")

COLORS = {
    "conflict":   "#E63946",
    "escalation": "#F4A261",
    "error":      "#2A9D8F",
    "fp":         "#457B9D",
    "time":       "#6A4C93",
    "precision":  "#1D7874",
    "recall":     "#EE9B00",
}

def _save(fig, filename):
    os.makedirs(GRAPHS_DIR, exist_ok=True)
    path = os.path.join(GRAPHS_DIR, filename)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {path}")


def _policy_labels(results):
    return [r["policy"].replace("policy_eval_","").replace(".rbac","").capitalize()
            for r in results]


def bar_conflicts_detected(results):
    labels = _policy_labels(results)
    conf   = [r["detected_conflicts"]        for r in results]
    esc    = [r["detected_escalation_paths"] for r in results]
    errs   = [r["detected_semantic_errors"]  for r in results]
    x = np.arange(len(labels))
    w = 0.25
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - w,    conf, w, label="SoD Conflicts",       color=COLORS["conflict"],   zorder=3)
    ax.bar(x,        esc,  w, label="Escalation Paths",     color=COLORS["escalation"], zorder=3)
    ax.bar(x + w,    errs, w, label="Semantic Errors",      color=COLORS["error"],      zorder=3)
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Count");  ax.set_title("Issues Detected per Policy", fontsize=13, fontweight="bold")
    ax.legend();  ax.grid(axis="y", alpha=0.4);  ax.set_axisbelow(True)
    _save(fig, "conflicts_detected.png")


def bar_analysis_time(results):
    labels = _policy_labels(results)
    times  = [r["analysis_time_ms"] for r in results]
    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.bar(labels, times, color=COLORS["time"], zorder=3)
    ax.bar_label(bars, fmt="%.1f ms", padding=3, fontsize=9)
    ax.set_ylabel("Analysis Time (ms)")
    ax.set_title("Analysis Time per Policy", fontsize=13, fontweight="bold")
    ax.grid(axis="y", alpha=0.4);  ax.set_axisbelow(True)
    _save(fig, "analysis_time.png")


def bar_false_positive_rate(results):
    labels = _policy_labels(results)
    fp_rates  = [r["false_positive_rate_pct"]  for r in results]
    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.bar(labels, fp_rates, color=COLORS["fp"], zorder=3)
    ax.bar_label(bars, fmt="%.1f%%", padding=3, fontsize=9)
    ax.set_ylabel("False-Positive Rate (%)")
    ax.set_title("False-Positive Rate per Policy", fontsize=13, fontweight="bold")
    ax.set_ylim(0, max(max(fp_rates)+10, 10))
    ax.grid(axis="y", alpha=0.4);  ax.set_axisbelow(True)
    _save(fig, "false_positive_rate.png")


def bar_stacked_breakdown(results):
    labels  = _policy_labels(results)
    conf    = np.array([r["detected_conflicts"]        for r in results])
    esc     = np.array([r["detected_escalation_paths"] for r in results])
    errs    = np.array([r["detected_semantic_errors"]  for r in results])
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(labels, conf, color=COLORS["conflict"],   label="SoD Conflicts",   zorder=3)
    ax.barh(labels, esc,  left=conf,                  color=COLORS["escalation"], label="Escalation Paths", zorder=3)
    ax.barh(labels, errs, left=conf+esc,              color=COLORS["error"],    label="Semantic Errors",  zorder=3)
    ax.set_xlabel("Issue Count")
    ax.set_title("Issue Breakdown per Policy (Stacked)", fontsize=13, fontweight="bold")
    ax.legend(loc="lower right")
    ax.grid(axis="x", alpha=0.4);  ax.set_axisbelow(True)
    _save(fig, "stacked_breakdown.png")


def line_precision_recall(results):
    labels    = _policy_labels(results)
    precision = [r["precision_pct"] for r in results]
    recall    = [r["recall_pct"]    for r in results]
    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(x, precision, "o-", color=COLORS["precision"], linewidth=2, label="Precision %", zorder=3)
    ax.plot(x, recall,    "s-", color=COLORS["recall"],    linewidth=2, label="Recall %",    zorder=3)
    ax.set_xticks(list(x));  ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Percentage (%)")
    ax.set_title("Precision and Recall per Policy", fontsize=13, fontweight="bold")
    ax.set_ylim(0, 110);  ax.legend();  ax.grid(alpha=0.4);  ax.set_axisbelow(True)
    _save(fig, "precision_recall.png")


def bar_manual_vs_detected(results):
    """Compare ground-truth (manual) vs detected totals."""
    labels   = _policy_labels(results)
    manual   = [r["expected_conflicts"] + r["expected_escalation_paths"] + r["expected_semantic_errors"]
                for r in results]
    detected = [r["detected_conflicts"] + r["detected_escalation_paths"] + r["detected_semantic_errors"]
                for r in results]
    x = np.arange(len(labels))
    w = 0.35
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - w/2, manual,   w, label="Manual (Ground Truth)", color="#2C3E50", zorder=3)
    ax.bar(x + w/2, detected, w, label="Compiler Detected",     color=COLORS["precision"], zorder=3)
    ax.set_xticks(x);  ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Issue Count")
    ax.set_title("Manual Analysis vs Compiler Detection", fontsize=13, fontweight="bold")
    ax.legend();  ax.grid(axis="y", alpha=0.4);  ax.set_axisbelow(True)
    _save(fig, "manual_vs_detected.png")


def main():
    if not os.path.exists(JSON_PATH):
        print(f"ERROR: {JSON_PATH} not found. Run evaluate.py first.")
        sys.exit(1)

    with open(JSON_PATH, encoding="utf-8") as f:
        data = json.load(f)

    results = [r for r in data["results"] if "error" not in r]
    if not results:
        print("No valid results to plot.")
        sys.exit(1)

    print(f"\nGenerating graphs for {len(results)} policies ...\n")
    bar_conflicts_detected(results)
    bar_analysis_time(results)
    bar_false_positive_rate(results)
    bar_stacked_breakdown(results)
    line_precision_recall(results)
    bar_manual_vs_detected(results)
    print(f"\nAll graphs saved to: {GRAPHS_DIR}\n")


if __name__ == "__main__":
    main()
