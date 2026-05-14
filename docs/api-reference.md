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

## GET /audit

Query structured scan records from the audit log.  Auth required (Bearer token).

**Query parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `verdict` | string | No | Filter by verdict: `ALLOW`, `WARN`, or `BLOCK` |
| `package` | string | No | Filter by package name (without version) |
| `since` | string | No | Return only records newer than this ISO-8601 timestamp |
| `last` | integer | No | Maximum records to return (default `100`, max `1000`) |

**Response 200**

```json
{
  "events": [
    {
      "ts": "2026-05-14T10:00:00+00:00",
      "package": "lodash@4.17.21",
      "verdict": "ALLOW",
      "score": 2.7,
      "signals": [],
      "ai_suggested": false,
      "project_path": "/home/user/myapp",
      "cached": false
    }
  ],
  "total": 1
}
```

**Response 422** — `verdict` is not one of `ALLOW`, `WARN`, `BLOCK`.

**Example**

```bash
curl -s "http://127.0.0.1:7355/api/v1/audit?verdict=BLOCK&last=20" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## GET /policy

Return the resolved project policy for a given path.  Auth required.

**Query parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `project_path` | string | **Yes** | Absolute path of the project to resolve policy for |

**Response 200**

```json
{
  "project_path": "/home/user/myapp",
  "policy_file": "/home/user/myapp/.cidas/policy.json",
  "resolved": {
    "block_list": ["bad-pkg"],
    "trust_list": [],
    "warn_requires_confirmation": true
  }
}
```

`policy_file` is `null` when no `.cidas/policy.json` was found in any ancestor directory.

---

## POST /audit/override

Record a user "Proceed Anyway" override event.  Called by the VS Code extension
when a developer proceeds past a WARN or BLOCK dialog.

**Request body**

```json
{
  "package_name": "lodahs",
  "version": "1.0.0",
  "verdict_was": "WARN"
}
```

**Response 200**

```json
{ "logged": true, "package": "lodahs@1.0.0", "event": "user_override" }
```

**Response 422** — `package_name` missing from body.

---

## Timing header

Every response includes `X-CIDAS-Latency-Ms` showing server-side processing
time in milliseconds.

---

## Error format

```json
{ "detail": "error description" }
```
