"""generate_baseline_comparison.py — combine CIDAS's own evaluation results
with the external baseline-comparison runs into one table.

Reads:
    results/latest.json           (CIDAS, from evaluate.py)
    results/baseline_npm_audit.json
    results/baseline_osv_scanner.json
    results/baseline_socket.json  (infeasibility note, not a completed run — see file)
    results/baseline_guarddog.json (if present)

Writes:
    results/baseline_comparison.md

Deliberately does not fabricate numbers for tools that weren't run
(Socket.dev, Snyk, Amalfi) — each is reported with its actual status
(completed / infeasible-on-available-quota / cited-numbers-only /
not-attempted) rather than silently omitted or filled with a guess.

Usage
-----
    python daemon/eval/generate_baseline_comparison.py
"""
from __future__ import annotations

import json
from pathlib import Path

_THIS_DIR = Path(__file__).parent
RESULTS_DIR = _THIS_DIR / "results"


def _load(name: str) -> dict | None:
    path = RESULTS_DIR / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _row_from_overall(tool: str, doc: dict, execution_stage: str, notes: str = "") -> dict:
    metrics = doc.get("metrics", {})
    overall = metrics.get("overall", {})
    latency = metrics.get("latency", {})
    return {
        "tool": tool,
        "precision": overall.get("precision"),
        "recall": overall.get("recall"),
        "f1": overall.get("f1"),
        "fpr": overall.get("false_positive_rate"),
        "completion_rate": doc.get("completion_rate"),
        "median_latency_ms": latency.get("median_ms"),
        "execution_stage": execution_stage,
        "notes": notes,
    }


def _category_row(tool: str, doc: dict, category: str, label: str) -> dict:
    cat_metrics = (doc.get("metrics", {}).get("per_ground_truth", {}) or {}).get(category, {})
    return {
        "tool": label,
        "precision": cat_metrics.get("precision"),
        "recall": cat_metrics.get("recall"),
        "f1": cat_metrics.get("f1"),
        "fpr": None,
        "completion_rate": round(
            (cat_metrics.get("TP", 0) + cat_metrics.get("FP", 0) + cat_metrics.get("TN", 0) + cat_metrics.get("FN", 0))
            / max(1, sum(cat_metrics.get(k, 0) for k in ("TP", "FP", "TN", "FN", "ERROR"))),
            4,
        ),
        "median_latency_ms": None,
        "execution_stage": "—",
        "notes": f"TP={cat_metrics.get('TP')} FN={cat_metrics.get('FN')} ERROR={cat_metrics.get('ERROR')} "
                 f"(among completed scans only, i.e. excluding the {cat_metrics.get('ERROR')} records "
                 f"that structurally couldn't install — purged/nonexistent versions).",
    }


def main() -> None:
    rows: list[dict] = []

    cidas = _load("latest.json")
    if cidas:
        rows.append(_row_from_overall(
            "CIDAS", cidas, "pre-install",
            "Production weights (0.30/0.35/0.35); own labelled corpus.",
        ))

    npm_audit = _load("baseline_npm_audit.json")
    if npm_audit:
        rows.append(_row_from_overall(
            "npm audit", npm_audit, "post-install (or on-demand)",
            f"npm {npm_audit.get('npm_version', '?')}. Advisory-database-only: "
            f"no name-existence, typosquat, or behavioral signal — pooled recall reflects a corpus "
            f"mostly outside its designed scope, not just tool weakness. See malicious-only row below "
            f"for its recall within the threat class it's actually built for. "
            f"error_reasons={json.dumps(npm_audit.get('error_reasons', {}))}",
        ))
        rows.append(_category_row("npm audit", npm_audit, "malicious", "&nbsp;&nbsp;↳ npm audit (malicious only)"))

    osv = _load("baseline_osv_scanner.json")
    if osv:
        rows.append(_row_from_overall(
            "OSV-Scanner", osv, "post-install (or on-demand)",
            f"{osv.get('osv_scanner_version', '?').splitlines()[0] if osv.get('osv_scanner_version') else '?'}. "
            f"Same advisory-database scope as npm audit but a broader/differently-curated "
            f"vulnerability DB (OSV.dev). Pooled recall (0.39) is dragged down by typosquat/"
            f"hallucinated categories it has no mechanism to detect by design (no name-similarity or "
            f"existence check) — see malicious-only row below for recall within its actual scope. "
            f"error_reasons={json.dumps(osv.get('error_reasons', {}))}",
        ))
        rows.append(_category_row("OSV-Scanner", osv, "malicious", "&nbsp;&nbsp;↳ OSV-Scanner (malicious only)"))

    socket = _load("baseline_socket.json")
    if socket:
        rows.append({
            "tool": "Socket.dev",
            "precision": None, "recall": None, "f1": None, "fpr": None,
            "completion_rate": None, "median_latency_ms": None,
            "execution_stage": "pre-install (CI/GitHub App) or on-demand API",
            "notes": socket.get("notes", socket.get("status", "not attempted")),
        })
    else:
        rows.append({
            "tool": "Socket.dev", "precision": None, "recall": None, "f1": None, "fpr": None,
            "completion_rate": None, "median_latency_ms": None,
            "execution_stage": "pre-install (CI/GitHub App) or on-demand API",
            "notes": "Not attempted in this pass.",
        })

    rows.append({
        "tool": "Snyk", "precision": None, "recall": None, "f1": None, "fpr": None,
        "completion_rate": None, "median_latency_ms": None,
        "execution_stage": "post-install / CI",
        "notes": "Proprietary, commercial API; detection logic not fully documented publicly. "
                 "Live comparison not attempted this pass — cost/licensing constraints unconfirmed. "
                 "Stated here explicitly as a scoping decision, not a silent omission.",
    })

    rows.append({
        "tool": "Amalfi", "precision": None, "recall": None, "f1": None, "fpr": None,
        "completion_rate": None, "median_latency_ms": None,
        "execution_stage": "post-install (offline classifier)",
        "notes": "Cited-numbers comparison only (95 malicious packages found in 96,287 versions, "
                 "per the original paper). No live reproduction attempted: Amalfi's offline "
                 "classifier pipeline and source-reproducibility infrastructure are not public "
                 "in a runnable form.",
    })

    guarddog = _load("baseline_guarddog.json")
    if guarddog:
        rows.append(_row_from_overall(
            "GuardDog", guarddog, "on-demand (pre- or post-install)",
            f"error_reasons={json.dumps(guarddog.get('error_reasons', {}))}",
        ))

    lines = [
        "# CIDAS vs. Baseline Tools — Comparison Table",
        "",
        "Generated by `generate_baseline_comparison.py`. All tools run against the",
        "identical labelled corpus used for CIDAS's own evaluation, where a live run",
        "was completed — see each tool's own `notes` column for scope/status.",
        "",
        "**Corpus version note**: CIDAS, npm audit, and OSV-Scanner below are all run",
        "against corpus v1.1 (189 records — the original 179 plus 10 genuine Unicode-",
        "homoglyph typosquats added to validate CIDAS's homoglyph-normalization path).",
        "Socket.dev remains pinned to corpus v1.0 (179 records): its full-corpus run is",
        "already infeasible on the available API quota regardless of corpus size (see its",
        "row's notes), and none of the 3 live-tested external tools implement homoglyph/",
        "name-similarity detection, so the 10 new v1.1 records carry no comparative signal",
        "for that specific tool. This is a deliberate scope decision, not an oversight.",
        "",
        "**On pooled vs. per-category recall for npm audit / OSV-Scanner**: both tools are",
        "advisory-database scanners whose only detection mechanism is a filed CVE/GHSA",
        "advisory against a resolved version. Neither has any name-existence, typosquat, or",
        "behavioral signal — so a pooled recall computed across this corpus's typosquat and",
        "hallucinated categories understates what each tool actually does well. The indented",
        "`(malicious only)` rows below report recall restricted to the one category these",
        "tools are actually designed to catch, among records that could be scanned at all",
        "(excluding installs that failed outright due to a purged/nonexistent version — see",
        "each row's notes for the exact TP/FN/ERROR counts). Read this pair together: OSV-Scanner's",
        "malicious-only recall (0.83) is meaningfully higher than npm audit's (0.00) — a real",
        "difference in advisory-database coverage, not an artifact of corpus composition.",
        "",
        "| Tool | Precision | Recall | F1 | FPR | Completion | Median Latency | Execution Stage | Notes |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        def _fmt(v):
            if v is None:
                return "—"
            if isinstance(v, float):
                return f"{v:.4f}"
            return str(v)
        lines.append(
            f"| {r['tool']} | {_fmt(r['precision'])} | {_fmt(r['recall'])} | {_fmt(r['f1'])} | "
            f"{_fmt(r['fpr'])} | {_fmt(r['completion_rate'])} | {_fmt(r['median_latency_ms'])} | "
            f"{r['execution_stage']} | {r['notes']} |"
        )

    output = RESULTS_DIR / "baseline_comparison.md"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[generate-baseline-comparison] wrote {output}")
    print()
    print("\n".join(lines))


if __name__ == "__main__":
    main()
