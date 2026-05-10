# CIDAS — CI Dependency Analysis & Screening

A VS Code extension paired with a local Python daemon that screens npm packages
**before** they are installed, catching typosquatting, malware, AI-hallucinated
packages, and prompt injection in real time.

## How it works

```
npm install <pkg>
      │
      ▼
 npm-shim.js          intercept/npm-shim.js — transparent npm wrapper on PATH
  └─ integrity check  SHA-256 self-hash verified on every invocation
      │
      ▼
 CIDAS Daemon         Python · FastAPI · localhost:7355
  ├─ Auth             Bearer token (daemon.token, mode 0600) on all mutating endpoints
  ├─ Contextify       pillar 1 — project import fingerprint vs. candidate (30%)
  │                   └─ floor penalty (+20) when cosine similarity < 0.05
  ├─ Sentinel         pillar 2 — registry metadata, age, downloads, typosquat (35%)
  ├─ Shield           pillar 3 — lifecycle script patterns, tarball file scan (35%)
  │                   └─ downloads & scans up to 50 JS files per tarball
  └─ Aggregator       weighted risk score 0–100 → ALLOW / WARN / BLOCK
      │
      ▼
 SQLite              scan cache (name@version keys) · trust list (HMAC-verified)
      │
      ▼
 VS Code Extension    TypeScript
  ├─ Status bar       colour-coded live indicator
  ├─ Notification UI  block / warn / allow dialogs with details panel
  ├─ Interceptor      package.json watcher — scans newly added deps on save
  └─ SentinelHook     terminal listener — tags AI-suggested packages
```

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10 or later |
| Node.js | 18 or later |
| npm | 9 or later |
| VS Code | 1.89 or later |
| Git | any recent |

> **Windows users:** run all `bash` commands inside **Git Bash** or **WSL2**.
> PowerShell is not supported for the daemon or shim setup steps.

---

## Installation

### 1. Clone the repository

```bash
git clone <repo-url> cidas
cd cidas
```

### 2. Configure environment

```bash
cp .env.example .env
```

The defaults work out of the box. No changes are required for a local demo.
If you want to customise thresholds or the daemon port, edit `.env` before
starting the daemon.

Key variables:

```
DAEMON_PORT=7355          # port the daemon listens on
BLOCK_THRESHOLD=80        # risk score that triggers BLOCK
WARN_THRESHOLD=40         # risk score that triggers WARN
CONTEXT_WEIGHT=0.30       # weight for project-context similarity checks
SENTINEL_WEIGHT=0.35      # weight for registry reputation checks
SHIELD_WEIGHT=0.35        # weight for script/injection scanning
```

### 3. Start the daemon

```bash
bash scripts/start-daemon.sh
```

This script:
- Creates a Python virtual environment at `daemon/.venv` if one doesn't exist
- Installs all dependencies via `pip install -e ".[dev]"`
- Starts the FastAPI server on `http://127.0.0.1:7355`
- Writes the PID to `.cidas.pid`

Verify the daemon is running:

```bash
curl http://127.0.0.1:7355/api/v1/health
# → {"status":"ok","version":"0.1.0"}
```

Swagger UI is also available at `http://127.0.0.1:7355/docs`.

### 4. Install the VS Code extension

```bash
cd extension
npm install
npm run compile
```

Then in VS Code:
1. Open the `cidas` folder
2. Press **F5** (Run Extension)
3. A new VS Code window opens with CIDAS active
4. Check the status bar (bottom-left) — it should show `CIDAS ready`

### 5. Install the npm shim

```bash
bash intercept/install-shim.sh
```

This installs a transparent `npm` wrapper at `~/.cidas/npm` and prepends
`~/.cidas` to your `PATH`. Open a new terminal (or `source ~/.bashrc`) for
the change to take effect.

The shim computes a SHA-256 hash of itself on every invocation and refuses to
run if the hash does not match the value recorded in `~/.cidas/shim.sha256`.
To regenerate the expected hash after updating the shim:

```bash
bash intercept/sign-shim.sh
```

Verify the shim is on PATH:

```bash
which npm
# → /home/<user>/.cidas/npm
```

To remove the shim:

```bash
bash intercept/uninstall-shim.sh
```

---

## Authentication

All mutating endpoints (`/scan`, `/trust`, `/cache`, `/cache/invalidate`,
`/trust/verify`) require a Bearer token.

The daemon generates a 64-character hex token on first start, stores it at
`~/.cidas/daemon.token` (mode `0600`), and reuses it on restart. The VS Code
extension and npm shim read the token automatically from that path.

To make manual `curl` calls:

```bash
TOKEN=$(cat ~/.cidas/daemon.token)

curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"lodash","project_path":"."}'
```

Read-only endpoints (`/health`, `/audit`) do not require authentication.

---

## Manual scan examples

### Safe package

```bash
TOKEN=$(cat ~/.cidas/daemon.token)

curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"lodash","project_path":".","ai_suggested":false}' \
  | python3 -m json.tool
```

Expected: `"decision": "ALLOW"`, `risk_score` near 0.

### Typosquatted package

```bash
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"lodahs","project_path":".","ai_suggested":false}' \
  | python3 -m json.tool
```

Expected: `"decision": "WARN"`, flag `typosquat_detected`, `similar_to: "lodash"`.

### AI-hallucinated package

```bash
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"totally-fake-pkg-xyz999","project_path":".","ai_suggested":true}' \
  | python3 -m json.tool
```

Expected: `"decision": "BLOCK"`, flag `package_not_found`, score ≥ 80.

### Trust bypass

```bash
TOKEN=$(cat ~/.cidas/daemon.token)

# Add a package to the trust list (HMAC-protected)
curl -s -X POST http://127.0.0.1:7355/api/v1/trust \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"my-internal-lib"}'

# Subsequent scans return ALLOW immediately (no pillar analysis)
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"my-internal-lib","project_path":"."}'

# Audit the full trust list for HMAC integrity
curl -s http://127.0.0.1:7355/api/v1/trust/verify \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -m json.tool
```

### Emergency cache invalidation

```bash
# Evict a specific version from the scan cache
curl -s -X POST http://127.0.0.1:7355/api/v1/cache/invalidate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"lodash","version":"4.17.20"}'

# Evict all cached versions of a package
curl -s -X POST http://127.0.0.1:7355/api/v1/cache/invalidate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"lodash","version":"*"}'
```

---

## Shim interception examples

With the shim installed and the daemon running, open a new terminal:

```bash
npm install lodash          # [CIDAS ALLOW] Package passed screening
npm install lodahs          # [CIDAS WARNING] typosquat_detected — similar to lodash
CIDAS_BYPASS=1 npm install  # bypass all checks (emergency escape hatch)
```

---

## Analysis pillars

| Pillar | Weight | What it checks |
|---|---|---|
| **Contextify** | 30% | Embeds existing project imports; cosine similarity to candidate description. Flags packages that are semantically unrelated to the project's tech stack. Applies a floor penalty of +20 when similarity < 0.05 ("alien to project"). |
| **Sentinel** | 35% | NPM registry: package age, monthly downloads, maintainer count, repository presence. Levenshtein typosquat detection against top packages. Full hallucination check for AI-suggested packages. |
| **Shield** | 35% | Lifecycle script regex scan: `eval`, `curl`/`wget`, base64 decode, `process.env` exfiltration, crypto-miner strings, obfuscation, prompt injection in README. Downloads and scans up to 50 JS files from the published tarball for require()-time exfiltration patterns. |
| **Aggregator** | — | `score = 0.30×contextify + 0.35×sentinel + 0.35×shield`. Maps to ALLOW (<40) / WARN (40–79) / BLOCK (≥80). Results cached in SQLite by `name@version` for 1 hour. |

### Contextify floor rule

When the cosine similarity between the candidate package and the project's
import fingerprint is below **0.05**, the aggregator adds a flat **+20** penalty
and tags the result with `alien_to_project`. This catches zero-day packages with
no semantic relationship to the project that would otherwise score low across all
pillars.

A per-machine override for Contextify's weight is available in the admin config
(see below).

### Shield tarball file scan

After evaluating lifecycle scripts, Shield downloads the package tarball from
the npm registry and scans up to **50 JavaScript files** (≤ 200 KB each) for
patterns that only activate at require()-time:

| Pattern | Signal | Score contribution |
|---|---|---|
| `process.env.SECRET` within 5 lines of an HTTP fetch | `env_exfil_near_http` | +30 |
| `require('dns')` + 13+ char subdomain | `dns_long_subdomain` | +35 |
| `\x` hex escape density > 5% | `hex_density` | +25 |

File-scan findings are weighted at **0.6** of their raw score to avoid
over-flagging heavily minified or bundled packages. The scan can be disabled
per-machine via the admin config.

---

## Decision thresholds

| Decision | Score range | Behaviour |
|---|---|---|
| `ALLOW` | 0–39 | Install proceeds; green notification in VS Code |
| `WARN` | 40–79 | Install proceeds with a dismissible warning dialog |
| `BLOCK` | 80–100 | Shim exits 1 (install aborted); VS Code shows blocking dialog |

Thresholds are configurable via `BLOCK_THRESHOLD` and `WARN_THRESHOLD` in `.env`.

---

## Trust list integrity

Every package added to the trust list via `POST /trust` is protected by an
HMAC-SHA256 tag keyed on the daemon token. On every scan, `check_trust` verifies
the tag and returns one of four statuses:

| Status | Meaning | Scan outcome |
|---|---|---|
| `verified` | HMAC matches — row is authentic | ALLOW, skip pillars |
| `legacy_no_mac` | Row added before v3 (no HMAC) | WARN (score 40), re-add recommended |
| `tampered` | HMAC mismatch — SQLite file edited directly | Full pillar scan + `trust_tamper_detected` flag |
| `unknown` | Package not in trust list | Full pillar scan |

Tamper events are logged at `CRITICAL` level. The `/trust/verify` endpoint
returns a full audit of every row's HMAC status.

---

## Version-keyed cache

The scan cache stores results keyed by `name@version` (e.g. `lodash@4.17.21`,
`axios@latest`). This prevents a safe `1.0.0` result from masking a malicious
`1.0.1`. The offline-allow cache used by the npm shim uses the same key format.

Use `POST /cache/invalidate` for immediate eviction after a malicious-package
disclosure, without waiting for TTL expiry.

---

## Admin config

Create `~/.cidas/config.json` to override per-machine settings without editing
`.env`:

```json
{
  "bypass_disabled": true,
  "package_file_scan": false,
  "contextify_weight": 0.40
}
```

| Key | Type | Effect |
|---|---|---|
| `bypass_disabled` | bool | Disables `CIDAS_BYPASS=1` emergency escape hatch |
| `package_file_scan` | bool | Set `false` to skip tarball file scanning (faster, lower network use) |
| `contextify_weight` | float 0.0–0.5 | Overrides Contextify's pillar weight; sentinel/shield split the remainder equally |

---

## REST API reference

All endpoints are prefixed with `/api/v1`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | — | Liveness probe |
| `POST` | `/scan` | Bearer | Screen a package; returns decision + pillar scores |
| `POST` | `/trust` | Bearer | Add a package to the HMAC-protected trust list |
| `GET` | `/trust/verify` | Bearer | Audit all trust-list HMAC tags |
| `DELETE` | `/cache` | Bearer | Purge all expired scan cache entries |
| `POST` | `/cache/invalidate` | Bearer | Evict a specific package version (or all versions) |
| `GET` | `/audit` | — | Last 100 trust-bypass events from audit.log |

---

## Running tests

### Daemon (Python — pytest)

```bash
# From the project root, with the venv active:
source daemon/.venv/bin/activate
pytest daemon/tests/ -v --cov=daemon --cov-report=term-missing
```

Or use the convenience script (creates venv automatically):

```bash
bash scripts/run-tests.sh
```

**121 tests · 89%+ coverage** across all daemon modules.

### Extension (TypeScript — Vitest)

```bash
cd extension
npm install
npx vitest run --coverage --reporter=verbose
```

**76 tests · 80% statement coverage** across all five testable modules
(`daemonClient`, `interceptor`, `notificationUI`, `sentinelHook`, `statusBar`).

---

## Threat coverage

| Attack vector | Detection |
|---|---|
| Typosquatting (`lodasH`, `expres`) | Sentinel — Levenshtein distance |
| AI hallucination (model invents a package name) | Sentinel — `ai_suggested` + registry 404 |
| Malicious `postinstall` (curl, eval, env exfil) | Shield — lifecycle script scan |
| Require()-time exfiltration (env vars, DNS tunnel, hex obfuscation) | Shield — tarball file scan |
| Prompt injection in package README | Shield — injection pattern scan |
| Dependency confusion (unfamiliar package in established project) | Contextify floor penalty |
| Trust list tampering (direct SQLite edit) | Database — HMAC-SHA256 integrity check |
| Shim replacement / modification | npm-shim.js — SHA-256 self-hash check |

See [docs/threat-model.md](docs/threat-model.md) for the full adversary model.

---

## Project structure

```
cidas/
├── daemon/                 Python FastAPI daemon
│   ├── pillars/            Four analysis pillars
│   │   ├── contextify.py   Embedding-based project context (30% weight)
│   │   ├── sentinel.py     Registry reputation & typosquat (35% weight)
│   │   ├── shield.py       Script scanning, injection & tarball file scan (35% weight)
│   │   └── aggregator.py   Weighted scoring, floor rule & verdict
│   ├── utils/              Shared utilities
│   │   ├── embeddings.py   Sentence embedding helpers
│   │   ├── npm_registry.py Registry lookups + tarball download
│   │   ├── offline_cache.py name@version offline-allow cache
│   │   └── logger.py       Structured logging
│   ├── tests/              121 pytest tests (89%+ coverage)
│   │   └── fixtures/       Fixture tarballs for Shield file-scan tests
│   ├── auth.py             Bearer token generation & verification
│   ├── config.py           Pydantic settings from .env
│   ├── database.py         SQLite scan cache (v@version) & HMAC trust list (schema v3)
│   ├── models.py           Shared Pydantic request/response models
│   ├── router.py           FastAPI endpoints
│   └── main.py             App factory & uvicorn entry point
├── extension/              VS Code extension (TypeScript)
│   └── src/
│       ├── daemonClient.ts HTTP client with fail-open fallback
│       ├── interceptor.ts  package.json watcher & dep diffing
│       ├── sentinelHook.ts terminal listener for AI-suggested packages
│       ├── statusBar.ts    Colour-coded status bar manager
│       ├── notificationUI.ts  Warn/block/allow dialogs & webview panel
│       └── extension.ts    Activation & command registration
├── intercept/              npm shim
│   ├── npm-shim.js         Transparent npm wrapper with SHA-256 self-check
│   ├── install-shim.sh     PATH injection installer
│   ├── sign-shim.sh        Regenerates ~/.cidas/shim.sha256
│   └── uninstall-shim.sh   Shim removal
├── scripts/
│   ├── start-daemon.sh     Daemon launcher with venv bootstrap
│   └── run-tests.sh        Combined pytest + vitest runner
├── docs/
│   ├── architecture.md     Component diagram & data flow
│   ├── api-reference.md    REST API documentation
│   └── threat-model.md     Adversary model & attack vector coverage
└── .env.example            Configuration template
```

---

## Docs

- [Architecture](docs/architecture.md) — component diagram and full data flow
- [Threat model](docs/threat-model.md) — adversary model and attack coverage
- [API reference](docs/api-reference.md) — REST endpoint reference with examples
