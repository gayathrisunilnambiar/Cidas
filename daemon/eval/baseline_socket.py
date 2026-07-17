"""baseline_socket.py — run the CIDAS eval corpus through Socket.dev's
batch-PURL API as a baseline comparison.

Unlike npm audit / OSV-Scanner (both post-install, advisory-database-only
scanners), Socket.dev's alert model covers install scripts, typosquats,
telemetry, native code, and other supply-chain-specific signals in addition
to known CVEs — making it the closest of the three baselines to CIDAS's own
threat scope, and the most informative comparison point.

Setup (one-time)
-----------------
Requires a Socket.dev account (Free tier: 1,000 scans/month) and an
organization-scoped API token with the `packages:list` scope (created in
the Socket dashboard). Export both before running:

    export SOCKET_API_TOKEN=<your-token>
    export SOCKET_ORG_SLUG=<your-org-slug>

These are eval-tooling-only credentials, not part of the CIDAS daemon's own
configuration (daemon/config.py) — do not add them to the repo's .env file.

API
---
POST https://api.socket.dev/v0/orgs/{org_slug}/purl?alerts=true
Authorization: Bearer <token>
Body: {"components": [{"purl": "pkg:npm/<name>@<version>"}, ...]}

Batched: up to 1024 PURLs per request (this script batches conservatively,
see _BATCH_SIZE, to stay well clear of request-size/timeout issues). A
non-existent package/version is not itself an HTTP error at the batch
level — Socket simply returns no entry (or an entry with no alerts) for
that PURL, which this script must distinguish from "genuinely clean" by
checking whether the PURL round-trips in the response at all.

Threat-scope note (for the paper's comparison discussion): Socket has no
concept of "this exact name was hallucinated by an LLM" as a distinct
signal — a hallucinated corpus record only "fails" here if the name isn't
resolvable as a real npm package at all (same scope limit as the other two
baselines, tracked as ERROR/reason "not-in-response", not FN).

Known feasibility limit — confirmed empirically, not from documentation
------------------------------------------------------------------------
The batch-PURL endpoint charges a flat 100 quota units per request
REGARDLESS of batch size (verified live: a batch of 4 PURLs was rejected
with "Requires 100, but token has only 11" after 3 earlier single/small
test requests had already consumed most of a starting pool). The publicly
advertised "1,000 scans/month" Free-tier figure does not describe this
per-request API quota — it likely refers to a different usage dimension
(e.g. CI/GitHub-App scans). Covering this corpus's 179 records in batches
of _BATCH_SIZE=50 needs ~4 requests (400 quota units); a token with only a
small starting pool cannot complete a full run. This script is verified
working end-to-end (endpoint, auth, NDJSON response parsing all confirmed
against live single/small-batch requests) — what's blocked is quota, not
correctness. Re-run once a token with sufficient quota (a paid tier, or a
quota top-up) is available.

Usage
-----
    python daemon/eval/baseline_socket.py
    python daemon/eval/baseline_socket.py --corpus malicious
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx

_THIS_DIR = Path(__file__).parent
sys.path.insert(0, str(_THIS_DIR))
from evaluate import _metrics_block, _safe_div  # noqa: E402  (reuse, don't reimplement)

CORPUS_DIR = _THIS_DIR / "corpus"
RESULTS_DIR = _THIS_DIR / "results"
ALL_CORPORA = ("malicious", "typosquat", "hallucinated", "benign")
_API_BASE = "https://api.socket.dev/v0"
_BATCH_SIZE = 50
_REQUEST_TIMEOUT = 60.0


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


def _to_purl(record: dict) -> str:
    name = record["package_name"]
    version = record.get("version")
    if not version or version == "latest":
        return f"pkg:npm/{name}"
    return f"pkg:npm/{name}@{version}"


async def _fetch_batch(
    client: httpx.AsyncClient, org_slug: str, token: str, purls: list[str],
) -> dict[str, dict]:
    """POST one batch of PURLs; return {purl: package_data_or_error_marker}."""
    url = f"{_API_BASE}/orgs/{org_slug}/purl"
    body = {"components": [{"purl": p} for p in purls]}
    try:
        resp = await client.post(
            url,
            json=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            params={"alerts": "true"},
            timeout=_REQUEST_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        return {p: {"error": f"request failed: {exc}"} for p in purls}

    if resp.status_code != 200:
        return {p: {"error": f"http {resp.status_code}: {resp.text[:200]}"} for p in purls}

    # The batch-PURL endpoint returns application/x-ndjson: one JSON object
    # per line, NOT a {"packages": [...]} wrapper (confirmed against the
    # live API — the reference doc's example response shape is misleading).
    packages: list[dict] = []
    for line in resp.text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            packages.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    # Match by (name, requested-version-or-None) rather than reconstructing
    # an exact purl string: a "latest"/unversioned request has no version in
    # the request purl, but the response always includes the *resolved*
    # version, so a naive exact-purl-string match silently mismatches every
    # unversioned request. Matching on name (+ version only when the request
    # specified one) is robust to that; the one known residual edge case is
    # a single batch requesting both an unversioned and a differently
    # -versioned lookup of the *same* package name, which this corpus does
    # not do (each record requests exactly one version or "latest").
    def _parse_purl(p: str) -> tuple[str, str | None]:
        body = p.removeprefix("pkg:npm/")
        if "@" in body:
            name, _, version = body.rpartition("@")
            return name, version
        return body, None

    by_key: dict[tuple[str, str | None], dict] = {}
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        if not name:
            continue
        by_key[(name, version)] = pkg
        by_key[(name, None)] = pkg  # also matchable by name alone for unversioned requests

    results: dict[str, dict] = {}
    for p in purls:
        name, version = _parse_purl(p)
        match = by_key.get((name, version))
        results[p] = match if match is not None else {"error": "not-in-response"}
    return results


def _classify_binary(ground_truth: str, result: dict) -> str:
    if "error" in result:
        return "ERROR"
    alerts = result.get("alerts") or []
    is_actually_positive = ground_truth in ("malicious", "typosquat", "hallucinated")
    is_predicted_positive = len(alerts) > 0
    if is_actually_positive and is_predicted_positive:
        return "TP"
    if is_actually_positive and not is_predicted_positive:
        return "FN"
    if not is_actually_positive and is_predicted_positive:
        return "FP"
    return "TN"


async def _run(corpora: list[str], output: Path) -> None:
    token = os.environ.get("SOCKET_API_TOKEN")
    org_slug = os.environ.get("SOCKET_ORG_SLUG")
    if not token or not org_slug:
        raise SystemExit(
            "SOCKET_API_TOKEN and SOCKET_ORG_SLUG must both be set in the environment.\n"
            "  export SOCKET_API_TOKEN=<your-token>\n"
            "  export SOCKET_ORG_SLUG=<your-org-slug>"
        )

    all_records: list[dict] = []
    for name in corpora:
        for r in _load_corpus(name):
            r["_corpus"] = name
            all_records.append(r)
    print(f"[baseline-socket] org={org_slug}")
    print(f"[baseline-socket] loaded {len(all_records)} records across {len(corpora)} corpora")
    print(f"[baseline-socket] batch size={_BATCH_SIZE}")

    purl_to_record: dict[str, dict] = {}
    purls: list[str] = []
    for r in all_records:
        p = _to_purl(r)
        purl_to_record[p] = r
        purls.append(p)

    results_by_purl: dict[str, dict] = {}
    async with httpx.AsyncClient() as client:
        for i in range(0, len(purls), _BATCH_SIZE):
            batch = purls[i : i + _BATCH_SIZE]
            print(f"[baseline-socket] batch {i // _BATCH_SIZE + 1} ({len(batch)} PURLs)...")
            batch_results = await _fetch_batch(client, org_slug, token, batch)
            results_by_purl.update(batch_results)

    per_ground_truth: dict[str, dict[str, int]] = defaultdict(
        lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    )
    overall: dict[str, int] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "ERROR": 0}
    error_reasons: dict[str, int] = defaultdict(int)

    for p, r in purl_to_record.items():
        res = results_by_purl.get(p, {"error": "missing-from-batch"})
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
        "tool": "socket.dev",
        "org_slug": org_slug,
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
    print(f"\n[baseline-socket] wrote results -> {output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python daemon/eval/baseline_socket.py",
        description="Run the CIDAS eval corpora through Socket.dev's batch-PURL API for a baseline comparison.",
    )
    parser.add_argument("--corpus", choices=ALL_CORPORA, help="Run only one corpus (default: all four).")
    parser.add_argument("--output", default=str(RESULTS_DIR / "baseline_socket.json"))
    args = parser.parse_args()

    corpora = [args.corpus] if args.corpus else list(ALL_CORPORA)
    asyncio.run(_run(corpora, Path(args.output)))


if __name__ == "__main__":
    main()
