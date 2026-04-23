# CIDAS Daemon API Reference

Base URL: `http://127.0.0.1:7979/api/v1`

All mutating endpoints require the `X-CIDAS-Secret` header when
`DAEMON_SECRET` is set in `.env`.

---

## GET /health

Returns daemon health and version. No authentication required.

**Response 200**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

## POST /screen

Screen an npm package before installation.

**Headers**

| Header | Required | Description |
|---|---|---|
| `Content-Type` | Yes | `application/json` |
| `X-CIDAS-Secret` | If configured | Shared secret from `.env` |

**Request body**

```json
{
  "package_name": "lodash",
  "version": "4.17.21",
  "project_root": "/home/user/my-project",
  "install_args": ["--save-dev"]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `package_name` | string | Yes | npm package name |
| `version` | string \| null | No | Specific version; `null` = latest |
| `project_root` | string \| null | No | Absolute path for Contextify pillar |
| `install_args` | string[] | No | Raw npm install arguments (informational) |

**Response 200**

```json
{
  "package_name": "lodash",
  "version": "4.17.21",
  "verdict": "ALLOW",
  "risk_score": 3.5,
  "cached": false,
  "message": "'lodash' passed all CIDAS checks (risk score 4/100).",
  "pillars": [
    {
      "pillar": "contextify",
      "score": 0.0,
      "signals": {
        "existing_import_count": 42,
        "max_similarity_to_existing": 0.91
      },
      "notes": "Package is semantically consistent with existing project imports."
    },
    {
      "pillar": "sentinel",
      "score": 0.0,
      "signals": {
        "is_likely_typosquat": false,
        "similar_to": "",
        "age_days": 2920,
        "weekly_downloads": 45000000,
        "maintainer_count": 3,
        "readme_length": 8400,
        "has_repository": true
      },
      "notes": "Typosquat: False. Metadata risk: 0.0."
    },
    {
      "pillar": "shield",
      "score": 0.0,
      "signals": {
        "vuln_ids": [],
        "vuln_count": 0,
        "vuln_score": 0.0,
        "lifecycle_hooks": false
      },
      "notes": "0 known CVE(s). Script risk: 0.0."
    }
  ]
}
```

**Verdict values**

| Verdict | Risk score | Meaning |
|---|---|---|
| `ALLOW` | < 40 | Safe to install |
| `WARN` | 40–79 | Moderate risk; user should review |
| `BLOCK` | ≥ 80 | High risk; install blocked by default |

**Response 401** — Missing or invalid `X-CIDAS-Secret`.

---

## DELETE /cache

Purge expired cache entries. Useful for forcing a re-screen.

**Response 200**
```json
{ "purged": 3 }
```

---

## Error format

All error responses use the default FastAPI exception schema:

```json
{
  "detail": "Invalid or missing X-CIDAS-Secret header"
}
```

---

## Interactive docs

The daemon exposes a Swagger UI at `http://127.0.0.1:7979/docs` when running
in development mode.
