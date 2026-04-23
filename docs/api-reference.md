# CIDAS Daemon API Reference

Base URL: `http://127.0.0.1:7355/api/v1`

Interactive Swagger UI: `http://127.0.0.1:7355/docs`

---

## GET /health

Liveness probe — no authentication required.

**Response 200**
```json
{ "status": "ok", "version": "0.1.0" }
```

---

## POST /scan

Screen an npm package before installation.

**Request body**

```json
{
  "package_name": "lodash",
  "version": "4.17.21",
  "project_path": "/home/user/my-project",
  "ai_suggested": false,
  "requesting_tool": "npm-shim"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `package_name` | string | **Yes** | npm package name |
| `version` | string \| null | No | Specific version; `null` = latest |
| `project_path` | string | **Yes** | Absolute path used by Contextify pillar |
| `ai_suggested` | boolean | No | `true` when the package came from an AI suggestion |
| `requesting_tool` | string \| null | No | Caller identifier, e.g. `"npm-shim"` |

**Response 200 — ALLOW example**

```json
{
  "package_name": "lodash",
  "version": "4.17.21",
  "decision": "ALLOW",
  "risk_score": 2.7,
  "contextify": { "score": 0.0, "confidence": 0.7, "flags": [], "metadata": { "similarity": 0.91 } },
  "sentinel":   { "score": 0.0, "confidence": 0.9, "flags": [], "metadata": { "ai_suggested": false, "hallucination_check": "skipped" } },
  "shield":     { "score": 0.0, "confidence": 0.8, "flags": [], "metadata": { "script_score": 0, "injection_score": 0 } },
  "alternatives": [],
  "explanation": "Package passed all checks (risk score 3/100).",
  "latency_ms": 42.1
}
```

**Decision values**

| Decision | Risk score | Meaning |
|---|---|---|
| `ALLOW` | < 40 | Safe to proceed |
| `WARN`  | 40–79 | Proceed with caution |
| `BLOCK` | ≥ 80 | Install blocked by default |

---

## POST /trust

Add a package to the local trust bypass list.  Future scans for this package
return `ALLOW` immediately without pillar analysis.

**Request body**
```json
{ "package_name": "my-internal-lib" }
```

**Response 200**
```json
{ "trusted": "my-internal-lib" }
```

**Response 422** — `package_name` missing from body.

---

## DELETE /cache

Purge all expired scan cache entries.

**Response 200**
```json
{ "purged": 3 }
```

---

## Timing header

Every response includes `X-CIDAS-Latency-Ms` showing server-side processing
time in milliseconds.

---

## Error format

```json
{ "detail": "error description" }
```
