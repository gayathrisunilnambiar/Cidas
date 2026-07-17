"""baseline_npm_audit.py — run the CIDAS eval corpus through `npm audit` as a
baseline comparison.

`npm audit` is a post-install, advisory-database-driven scanner: it flags a
package only if npm's registry has a filed CVE/GHSA advisory against the
resolved version. It has no name-existence check, no typosquat/name-similarity
signal, and no static/behavioral analysis of package content — it is expected
to have near-zero recall on this corpus except for the small number of
malicious records that correspond to a widely-reported, formally-advisoried
incident (e.g. the known-supply-chain-incident blocklist packages:
event-stream, flatmap-stream, ua-parser-js, coa, rc, node-ipc, eslint-scope —
several of which do have a filed advisory). This is the expected, honest
comparison point: npm audit is not a weaker version of CIDAS, it addresses a
narrower, different threat scope (known-CVE post-install detection vs.
pre-install behavioral/reputation/context screening).

Safety
------
Every corpus record is installed via `npm install <pkg>@<version> --ignore-scripts`
into a disposable temp directory. `--ignore-scripts` is mandatory here, not
optional: several corpus entries are genuinely malicious packages whose
lifecycle scripts are the actual attack payload (this is exactly what CIDAS's
own Shield pillar screens for pre-install) — running them for real to get an
npm-audit baseline number would be installing live malware. `npm audit` only
needs the resolved dependency tree/metadata, not script execution, so this
does not affect the audit result.

Known, confirmed scope limits (both counted as ERROR, not FN, per the same
explicit scoping decision used in baseline_guarddog.py):
- Hallucinated-corpus records: the package name doesn't exist on the registry
  at all, so `npm install` fails outright — not because npm audit is weak at
  hallucination detection, but because "this name doesn't exist" isn't a
  signal in its scope at all.
- Malicious-corpus records pinned to a version npm has since purged after the
  incident: `npm install <pkg>@<purged-version>` fails to resolve that exact
  version even though the package name itself still exists. This is tracked
  as a distinct error reason (`version-not-found`) from a fully nonexistent
  package (`package-not-found`), since they're different failure modes.

Usage
-----
    python daemon/eval/baseline_npm_audit.py
    python daemon/eval/baseline_npm_audit.py --corpus malicious
    python daemon/eval/baseline_npm_audit.py --concurrency 4
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

CORPUS_DIR = _THIS_DIR / "corpus"
RESULTS_DIR = _THIS_DIR / "results"
ALL_CORPORA = ("malicious", "typosquat", "hallucinated", "benign")
_INSTALL_TIMEOUT_SECONDS = 60
_AUDIT_TIMEOUT_SECONDS = 60


def _resolve_real_npm() -> str:
    """Return the path to the real npm binary, bypassing the CIDAS shim.

    On a machine with the CIDAS shim installed, plain "npm" on PATH resolves
    to intercept/npm-shim.js, not real npm — a baseline comparison run
    through the shim would not be an independent, reproducible npm-audit
    result (even though the shim fails open and passes through to real npm
    when the daemon is unreachable, this is incidental behavior, not a
    property a third party reproducing this baseline should have to rely
    on). The shim installer records the original binary's path in
    ~/.cidas/real-npm; fall back to plain "npm" when that marker is absent
    (i.e. the shim was never installed on this machine).
    """
    marker = Path.home() / ".cidas" / "real-npm"
    if marker.exists():
        real_path = marker.read_text(encoding="utf-8").strip()
        if real_path and Path(real_path).exists():
            return real_path
    return "npm"


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


def _extract_json(stdout: str) -> dict:
    """npm sometimes prints warnings before the JSON payload; be defensive
    about leading noise by taking the last brace-balanced object present."""
    stdout = stdout.strip()
    if not stdout:
        return {}
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        pass
    start = stdout.rfind("{")
    if start == -1:
        return {}
    depth = 0
    for i in range(start, len(stdout)):
        if stdout[i] == "{":
            depth += 1
        elif stdout[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(stdout[start : i + 1])
                except json.JSONDecodeError:
                    return {}
    return {}


def _classify_install_failure(stderr: str) -> str:
    """Distinguish a fully nonexistent package name from a purged-but-real
    version, since these are different, separately-reportable failure modes."""
    lowered = stderr.lower()
    if "no matching version found" in lowered or "e404" in lowered and "version" in lowered:
        return "version-not-found"
    if "404" in stderr or "not found" in lowered:
        return "package-not-found"
    return "other"


def _scan_one(record: dict) -> dict:
    """Install one record's package into a disposable temp dir (scripts
    disabled — see module docstring) and run `npm audit --json` against it.

    Returns {"flagged": bool, "vulnerabilities": int} on success, or
    {"error": str} when the package/version could not be installed at all.
    """
    package = record["package_name"]
    version = record.get("version")
    spec = package if not version or version == "latest" else f"{package}@{version}"

    tmp = tempfile.mkdtemp(prefix="cidas-npm-audit-")
    try:
        (Path(tmp) / "package.json").write_text(
            json.dumps({"name": "cidas-eval-tmp", "version": "1.0.0", "private": True}),
            encoding="utf-8",
        )
        try:
            install = subprocess.run(
                [_NPM_BIN, "install", spec, "--no-save", "--package-lock=false", "--ignore-scripts"],
                cwd=tmp, capture_output=True, text=True, timeout=_INSTALL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"install timeout after {_INSTALL_TIMEOUT_SECONDS}s"}

        if install.returncode != 0:
            reason = _classify_install_failure(install.stderr)
            return {"error": reason, "stderr": install.stderr[:300]}

        try:
            audit = subprocess.run(
                [_NPM_BIN, "audit", "--json"],
                cwd=tmp, capture_output=True, text=True, timeout=_AUDIT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"audit timeout after {_AUDIT_TIMEOUT_SECONDS}s"}

        payload = _extract_json(audit.stdout)
        if not payload:
            return {"error": f"no parseable audit output (exit {audit.returncode}): {audit.stderr[:200]}"}

        vuln_summary = (payload.get("metadata") or {}).get("vulnerabilities") or {}
        total = int(vuln_summary.get("total", 0) or 0)
        return {"flagged": total > 0, "vulnerabilities": total, "vulnerability_breakdown": vuln_summary}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _classify_binary(ground_truth: str, result: dict) -> str:
    """npm audit's verdict model is binary (flagged / clean), not
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
    npm_version = subprocess.run([_NPM_BIN, "--version"], capture_output=True, text=True).stdout.strip()

    all_records: list[dict] = []
    for name in corpora:
        for r in _load_corpus(name):
            r["_corpus"] = name
            all_records.append(r)
    print(f"[baseline-npm-audit] npm binary: {_NPM_BIN} (version {npm_version})")
    print(f"[baseline-npm-audit] loaded {len(all_records)} records across {len(corpora)} corpora")
    print(f"[baseline-npm-audit] concurrency={concurrency} (each record does a real npm install + audit)")

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
        "tool": "npm-audit",
        "npm_version": npm_version,
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
    print(f"\n[baseline-npm-audit] wrote results -> {output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python daemon/eval/baseline_npm_audit.py",
        description="Run the CIDAS eval corpora through `npm audit` for a baseline comparison.",
    )
    parser.add_argument("--corpus", choices=ALL_CORPORA, help="Run only one corpus (default: all four).")
    parser.add_argument("--output", default=str(RESULTS_DIR / "baseline_npm_audit.json"))
    parser.add_argument("--concurrency", type=int, default=3, help="Concurrent scans (default: 3).")
    args = parser.parse_args()

    corpora = [args.corpus] if args.corpus else list(ALL_CORPORA)
    asyncio.run(_run(corpora, args.concurrency, Path(args.output)))


if __name__ == "__main__":
    main()
