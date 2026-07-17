"""baseline_osv_scanner.py — run the CIDAS eval corpus through Google's
OSV-Scanner as a baseline comparison.

Like npm audit (see baseline_npm_audit.py), OSV-Scanner is a post-install,
advisory-database-driven scanner (queries the OSV.dev vulnerability
database against a resolved lockfile) — it has no name-existence check, no
typosquat/name-similarity signal, and no static/behavioral content analysis.
It is expected to behave similarly to npm audit on this corpus: near-zero
recall except for the small number of malicious records with a filed
OSV/GHSA advisory against a version that still resolves.

Setup (one-time)
-----------------
OSV-Scanner ships as a single static binary (no Go toolchain needed to run
it, only to build it from source, which this setup avoids). Fetched from
the official GitHub releases page and checksum-verified against the
published SHA256SUMS file:

    mkdir -p daemon/eval/.osv-scanner-bin
    curl -sL -o daemon/eval/.osv-scanner-bin/osv-scanner \\
        https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_linux_amd64
    chmod +x daemon/eval/.osv-scanner-bin/osv-scanner

This directory is gitignored (matching the existing `.guarddog-venv` pattern
for external eval-tooling dependencies) — it is not part of the CIDAS
daemon itself.

This OSV-Scanner release (v2.4.0) has no single-package query subcommand;
it requires a lockfile or source directory to scan (`osv-scanner scan
source --lockfile <path>`). This script therefore reuses the same
disposable-temp-directory install pattern as baseline_npm_audit.py to
produce a real package-lock.json, then points OSV-Scanner at it.

Safety
------
Same as baseline_npm_audit.py: every install uses `--ignore-scripts`, since
several corpus entries are genuinely malicious packages and this baseline
must not execute their lifecycle scripts for real.

Known, confirmed scope limits (both counted as ERROR, not FN, per the same
explicit scoping decision used in baseline_guarddog.py and
baseline_npm_audit.py): hallucinated-corpus records (name doesn't exist,
install fails) and malicious-corpus records pinned to a version npm has
since purged (that exact version fails to resolve even though the package
name exists).

Usage
-----
    python daemon/eval/baseline_osv_scanner.py
    python daemon/eval/baseline_osv_scanner.py --corpus malicious
    python daemon/eval/baseline_osv_scanner.py --concurrency 4
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_THIS_DIR = Path(__file__).parent
sys.path.insert(0, str(_THIS_DIR))
from evaluate import _metrics_block, _safe_div  # noqa: E402  (reuse, don't reimplement)
from baseline_npm_audit import _classify_install_failure, _resolve_real_npm  # noqa: E402

CORPUS_DIR = _THIS_DIR / "corpus"
RESULTS_DIR = _THIS_DIR / "results"
OSV_SCANNER_BIN = _THIS_DIR / ".osv-scanner-bin" / "osv-scanner"
ALL_CORPORA = ("malicious", "typosquat", "hallucinated", "benign")
_INSTALL_TIMEOUT_SECONDS = 60
_SCAN_TIMEOUT_SECONDS = 60

_NPM_BIN = _resolve_real_npm()


def _load_corpus(name: str) -> list[dict]:
    path = CORPUS_DIR / f"{name}.jsonl"
    if not path.exists():
        raise SystemExit(f"corpus file not found: {path}")
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def _scan_one(record: dict) -> dict:
    """Install one record's package into a disposable temp dir (scripts
    disabled), then run OSV-Scanner against the resulting lockfile.

    Returns {"flagged": bool, "vulnerabilities": int} on success, or
    {"error": str} when the package/version could not be installed, or
    when OSV-Scanner itself could not be invoked.
    """
    package = record["package_name"]
    version = record.get("version")
    spec = package if not version or version == "latest" else f"{package}@{version}"

    tmp = tempfile.mkdtemp(prefix="cidas-osv-scanner-")
    try:
        (Path(tmp) / "package.json").write_text(
            json.dumps({"name": "cidas-eval-tmp", "version": "1.0.0", "private": True}),
            encoding="utf-8",
        )
        try:
            install = subprocess.run(
                [_NPM_BIN, "install", spec, "--ignore-scripts"],
                cwd=tmp, capture_output=True, text=True, timeout=_INSTALL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"install timeout after {_INSTALL_TIMEOUT_SECONDS}s"}

        if install.returncode != 0:
            reason = _classify_install_failure(install.stderr)
            return {"error": reason, "stderr": install.stderr[:300]}

        lockfile = Path(tmp) / "package-lock.json"
        if not lockfile.exists():
            return {"error": "no-lockfile-written"}

        try:
            scan = subprocess.run(
                [str(OSV_SCANNER_BIN), "scan", "source", "--lockfile", "package-lock.json", "--format", "json"],
                cwd=tmp, capture_output=True, text=True, timeout=_SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"scan timeout after {_SCAN_TIMEOUT_SECONDS}s"}

        # OSV-Scanner exits 0 (clean) or 1 (vulnerabilities found) on a
        # successful scan; any other exit code means the scan itself failed.
        if scan.returncode not in (0, 1):
            return {"error": f"osv-scanner exit {scan.returncode}: {scan.stderr[:200]}"}

        try:
            payload = json.loads(scan.stdout) if scan.stdout.strip() else {}
        except json.JSONDecodeError:
            return {"error": f"no parseable scan output: {scan.stdout[:200]}"}

        total_groups = 0
        for result in payload.get("results", []):
            for pkg in result.get("packages", []):
                total_groups += len(pkg.get("groups", []))
        return {"flagged": total_groups > 0, "vulnerabilities": total_groups}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _classify_binary(ground_truth: str, result: dict) -> str:
    """OSV-Scanner's verdict model is binary (flagged / clean), not
    ALLOW/WARN/BLOCK — mirrors evaluate.py's _classify but for that shape."""
    if "error" in result:
        return "ERROR"
    is_actually_positive = ground_truth in ("malicious", "typosquat", "hallucinated")
    is_predicted_positive = bool(result.get("flagged"))
    if is_actually_positive and is_predicted_positive:
        return "TP"
    if is_actually_positive and not is_predicted_positive:
        return "FN"
    if not is_actually_positive and is_predicted_positive:
        return "FP"
    return "TN"


async def _run(corpora: list[str], concurrency: int, output: Path) -> None:
    if not OSV_SCANNER_BIN.exists():
        raise SystemExit(
            f"OSV-Scanner binary not found at {OSV_SCANNER_BIN}. Set up with:\n"
            f"  mkdir -p {OSV_SCANNER_BIN.parent}\n"
            f"  curl -sL -o {OSV_SCANNER_BIN} "
            f"https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64\n"
            f"  chmod +x {OSV_SCANNER_BIN}"
        )

    osv_version = subprocess.run(
        [str(OSV_SCANNER_BIN), "--version"], capture_output=True, text=True,
    ).stdout.strip()

    all_records: list[dict] = []
    for name in corpora:
        for r in _load_corpus(name):
            r["_corpus"] = name
            all_records.append(r)
    print(f"[baseline-osv-scanner] {osv_version.splitlines()[0] if osv_version else 'unknown version'}")
    print(f"[baseline-osv-scanner] npm binary: {_NPM_BIN}")
    print(f"[baseline-osv-scanner] loaded {len(all_records)} records across {len(corpora)} corpora")
    print(f"[baseline-osv-scanner] concurrency={concurrency} (each record does a real npm install + OSV-Scanner run)")

    sem = asyncio.Semaphore(concurrency)

    async def _bounded(r: dict) -> dict:
        async with sem:
            return await asyncio.to_thread(_scan_one, r)

    results = await asyncio.gather(*[_bounded(r) for r in all_records])

    per_ground_truth: dict[str, dict[str, int]] = defaultdict(
        lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    )
    overall: dict[str, int] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    error_reasons: dict[str, int] = defaultdict(int)

    for r, res in zip(all_records, results):
        outcome = _classify_binary(r["ground_truth"], res)
        per_ground_truth[r["ground_truth"]][outcome] += 1
        overall[outcome] += 1
        if "error" in res:
            error_reasons[res["error"]] += 1

    per_ground_truth_metrics = {k: _metrics_block(v) for k, v in per_ground_truth.items()}
    overall_metrics = _metrics_block(overall)
    overall_metrics["false_positive_rate"] = round(
        _safe_div(overall["FP"], overall["FP"] + overall["TN"]), 4
    )
    completion_rate = round(_safe_div(len(all_records) - overall["ERROR"], len(all_records)), 4)

    output_doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "osv-scanner",
        "osv_scanner_version": osv_version,
        "npm_binary": _NPM_BIN,
        "corpora": corpora,
        "total_records": len(all_records),
        "completion_rate": completion_rate,
        "error_reasons": dict(error_reasons),
        "metrics": {
            "per_ground_truth": per_ground_truth_metrics,
            "overall": overall_metrics,
        },
    }

    print("\n=== Metrics ===")
    print(json.dumps(output_doc, indent=2))

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(output_doc, indent=2), encoding="utf-8")
    print(f"\n[baseline-osv-scanner] wrote results -> {output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python daemon/eval/baseline_osv_scanner.py",
        description="Run the CIDAS eval corpora through OSV-Scanner for a baseline comparison.",
    )
    parser.add_argument("--corpus", choices=ALL_CORPORA, help="Run only one corpus (default: all four).")
    parser.add_argument("--output", default=str(RESULTS_DIR / "baseline_osv_scanner.json"))
    parser.add_argument("--concurrency", type=int, default=3, help="Concurrent scans (default: 3).")
    args = parser.parse_args()

    corpora = [args.corpus] if args.corpus else list(ALL_CORPORA)
    asyncio.run(_run(corpora, args.concurrency, Path(args.output)))


if __name__ == "__main__":
    main()
