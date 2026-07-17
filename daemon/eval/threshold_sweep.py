"""threshold_sweep.py — sensitivity sweep over CIDAS's configurable
thresholds, reporting precision/recall/F1/FPR as a function of each
parameter value rather than only the single chosen production value.

Two sweep mechanisms, matched to what each parameter actually affects:

Part A — Aggregator-level parameters (block_threshold, warn_threshold,
context_weight, sentinel_weight, shield_weight): these only affect how
already-computed per-pillar scores are *combined* into a verdict, not the
pillar scores themselves. This reuses the real `Aggregator` class directly
(daemon.pillars.aggregator.Aggregator, daemon.models.PillarScore) against
raw per-pillar scores already recorded in the local SQLite scan cache from
a prior full-corpus run — no daemon restart or live registry calls needed
per swept value. Deliberately does NOT hand-duplicate the aggregator's
logic a second time (the way ablation.py's local `_recompute_decision` did,
which caused this project's own ablation-vs-production F1 discrepancy
earlier this session) — this script imports and calls the real Aggregator.

Part B — Sentinel reputation-corroboration parameters
(reputation_ratio_threshold, mature_age_days, new_age_days): these affect
Sentinel's OWN score computation (inside check_reputation_disparity), not
just the aggregator's combination — so each swept value needs a fresh
`Sentinel().score(...)` call per record. Runs in-process (no daemon
needed), reusing this session's registry cache/rate-limiter so a full
sweep doesn't re-trip npm's rate limits.

Usage
-----
    python daemon/eval/threshold_sweep.py                  # both parts
    python daemon/eval/threshold_sweep.py --part aggregator # Part A only
    python daemon/eval/threshold_sweep.py --part sentinel   # Part B only
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

_THIS_DIR = Path(__file__).parent
_REPO_ROOT = _THIS_DIR.parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_THIS_DIR))

from evaluate import _metrics_block, _safe_div  # noqa: E402

from daemon.config import Settings, get_settings  # noqa: E402
from daemon.models import PillarScore  # noqa: E402
from daemon.pillars.aggregator import Aggregator  # noqa: E402
from daemon.pillars.sentinel import Sentinel  # noqa: E402

CORPUS_DIR = _THIS_DIR / "corpus"
RESULTS_DIR = _THIS_DIR / "results"
CACHE_DB = _REPO_ROOT / ".cidas_cache.db"
ALL_CORPORA = ("malicious", "typosquat", "hallucinated", "benign")


def _load_corpus(name: str) -> list[dict]:
    path = CORPUS_DIR / f"{name}.jsonl"
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            r = json.loads(line)
            r["_corpus"] = name
            records.append(r)
    return records


def _load_all_corpora() -> list[dict]:
    all_records: list[dict] = []
    for name in ALL_CORPORA:
        all_records.extend(_load_corpus(name))
    return all_records


def _classify(ground_truth: str, decision: str) -> str:
    is_actually_positive = ground_truth in ("malicious", "typosquat", "hallucinated")
    is_predicted_positive = decision in ("WARN", "BLOCK")
    if is_actually_positive and is_predicted_positive:
        return "TP"
    if is_actually_positive and not is_predicted_positive:
        return "FN"
    if not is_actually_positive and is_predicted_positive:
        return "FP"
    return "TN"


# ── Part A: Aggregator-level sweep, reusing cached pillar scores ─────────────

def _load_cached_pillar_scores() -> dict[str, dict]:
    """Return {package_key: {"contextify": PillarScore, "sentinel": ..., "shield": ...}}
    from the local scan cache written by a prior full-corpus evaluate.py run."""
    conn = sqlite3.connect(str(CACHE_DB))
    cur = conn.cursor()
    cur.execute("SELECT package_key, context_json, sentinel_json, shield_json FROM scan_cache")
    out: dict[str, dict] = {}
    for key, ctx_j, sen_j, shi_j in cur.fetchall():
        out[key] = {
            "contextify": PillarScore(**json.loads(ctx_j)),
            "sentinel": PillarScore(**json.loads(sen_j)),
            "shield": PillarScore(**json.loads(shi_j)),
        }
    return out


def _sweep_aggregator_param(
    records: list[dict],
    cached: dict[str, dict],
    param: str,
    values: list[float],
) -> list[dict]:
    """Sweep one Settings field (block_threshold, warn_threshold, or a
    pillar weight), holding the others at production defaults, using the
    real Aggregator against cached per-pillar scores."""
    base = get_settings()
    agg = Aggregator()
    rows: list[dict] = []
    for v in values:
        overrides = {param: v}
        settings = Settings(**{**base.model_dump(), **overrides})
        counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        missing = 0
        for r in records:
            key = f"{r['package_name']}@{r['version']}"
            pillars = cached.get(key)
            if pillars is None:
                missing += 1
                continue
            score, _ = agg.aggregate(
                pillars["contextify"], pillars["sentinel"], pillars["shield"], settings,
            )
            decision = agg.get_decision(score, settings)
            counts[_classify(r["ground_truth"], decision)] += 1
        metrics = _metrics_block(counts)
        metrics["false_positive_rate"] = round(_safe_div(counts["FP"], counts["FP"] + counts["TN"]), 4)
        rows.append({"param": param, "value": v, "missing_records": missing, **metrics})
    return rows


# ── Part B: Sentinel-level sweep, fresh Sentinel.score() calls ───────────────

async def _sweep_sentinel_param(
    records: list[dict],
    param: str,
    values: list[float],
    concurrency: int,
) -> list[dict]:
    base = get_settings()
    sem = asyncio.Semaphore(concurrency)
    rows: list[dict] = []

    for v in values:
        overrides = {param: v}
        swept = Settings(**{**base.model_dump(), **overrides})

        # sentinel.py did `from ..config import get_settings`, binding its
        # own module-level name at import time — patching daemon.config's
        # attribute does NOT affect that already-bound reference, so the
        # patch target must be sentinel's own name for it (same gotcha as
        # this session's disk_checker/get_package_size binding issue).
        import daemon.pillars.sentinel as sentinel_module
        original_get_settings = sentinel_module.get_settings
        sentinel_module.get_settings = lambda: swept

        try:
            sentinel = Sentinel()
            agg = Aggregator()
            # Sentinel-only weighting: reuse the real Aggregator (Stage-1
            # gates + Stage-2 weighted sum) rather than hand-copying the
            # gate list a second time — the exact anti-pattern that caused
            # this session's ablation.py/Aggregator sync bug. Contextify and
            # Shield are held at a neutral zero score/no-flags PillarScore
            # so only Sentinel's output (and its corroboration-threshold
            # dependence) drives the outcome.
            sentinel_only = Settings(**{**swept.model_dump(), "context_weight": 0.0,
                                        "sentinel_weight": 1.0, "shield_weight": 0.0})
            zero_pillar = PillarScore(score=0.0, confidence=0.0, flags=[], metadata={})

            async def _one(r: dict) -> str:
                async with sem:
                    sen_score = await sentinel.score(r["package_name"], r.get("ai_suggested", False), r.get("version"))
                    risk_score, _ = agg.aggregate(zero_pillar, sen_score, zero_pillar, sentinel_only)
                    decision = agg.get_decision(risk_score, sentinel_only)
                    return _classify(r["ground_truth"], decision)

            outcomes = await asyncio.gather(*[_one(r) for r in records])
        finally:
            sentinel_module.get_settings = original_get_settings

        counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        for o in outcomes:
            counts[o] += 1
        metrics = _metrics_block(counts)
        metrics["false_positive_rate"] = round(_safe_div(counts["FP"], counts["FP"] + counts["TN"]), 4)
        rows.append({"param": param, "value": v, **metrics})
        print(f"[threshold-sweep] {param}={v}: {metrics}")

    return rows


async def _run(part: str, concurrency: int, output: Path) -> None:
    records = _load_all_corpora()
    doc: dict = {"timestamp": datetime.now(timezone.utc).isoformat(), "total_records": len(records)}

    if part in ("all", "aggregator"):
        if not CACHE_DB.exists():
            print(f"[threshold-sweep] WARNING: {CACHE_DB} not found; skipping Part A (aggregator sweep). "
                  f"Run daemon/eval/evaluate.py against a live daemon first to populate the scan cache.")
        else:
            cached = _load_cached_pillar_scores()
            print(f"[threshold-sweep] Part A: {len(cached)} cached pillar-score records loaded")
            doc["aggregator_sweep"] = {
                "block_threshold": _sweep_aggregator_param(records, cached, "block_threshold", [60, 70, 80, 90, 95]),
                "warn_threshold": _sweep_aggregator_param(records, cached, "warn_threshold", [20, 30, 40, 50, 60]),
                "context_weight": _sweep_aggregator_param(records, cached, "context_weight", [0.0, 0.15, 0.30, 0.45, 0.60]),
                "sentinel_weight": _sweep_aggregator_param(records, cached, "sentinel_weight", [0.15, 0.25, 0.35, 0.45, 0.55]),
                "shield_weight": _sweep_aggregator_param(records, cached, "shield_weight", [0.15, 0.25, 0.35, 0.45, 0.55]),
            }

    if part in ("all", "sentinel"):
        print("[threshold-sweep] Part B: sweeping Sentinel reputation-corroboration thresholds "
              "(live registry calls, rate-limited — this will take a while)")
        doc["sentinel_sweep"] = {
            "reputation_ratio_threshold": await _sweep_sentinel_param(
                records, "reputation_ratio_threshold", [0.01, 0.05, 0.10, 0.20], concurrency,
            ),
            "mature_age_days": await _sweep_sentinel_param(
                records, "mature_age_days", [180, 365, 545, 730], concurrency,
            ),
            "new_age_days": await _sweep_sentinel_param(
                records, "new_age_days", [7, 15, 30, 60], concurrency,
            ),
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"\n[threshold-sweep] wrote results -> {output}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python daemon/eval/threshold_sweep.py")
    parser.add_argument("--part", choices=("all", "aggregator", "sentinel"), default="all")
    parser.add_argument("--concurrency", type=int, default=2, help="Concurrency for Part B live calls (default: 2, conservative given the shared rate limiter).")
    parser.add_argument("--output", default=str(RESULTS_DIR / "threshold_sweep.json"))
    args = parser.parse_args()
    asyncio.run(_run(args.part, args.concurrency, Path(args.output)))


if __name__ == "__main__":
    main()
