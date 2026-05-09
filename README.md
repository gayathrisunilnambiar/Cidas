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
      │
      ▼
 CIDAS Daemon         Python · FastAPI · localhost:7355
  ├─ Contextify       pillar 1 — project import fingerprint vs. candidate (15%)
  ├─ Sentinel         pillar 2 — registry metadata, age, downloads, typosquat (40%)
  ├─ Shield           pillar 3 — lifecycle script patterns, prompt injection (45%)
  └─ Aggregator       weighted risk score 0–100 → ALLOW / WARN / BLOCK
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
SENTINEL_WEIGHT=0.40      # weight for registry reputation checks
SHIELD_WEIGHT=0.45        # weight for script/injection scanning
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

Verify:

```bash
which npm
# → /home/<user>/.cidas/npm
```

To remove the shim:

```bash
bash intercept/uninstall-shim.sh
```

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

**48 tests · 89% coverage** across all daemon modules.

### Extension (TypeScript — Vitest)

```bash
cd extension
npm install
npx vitest run --coverage --reporter=verbose
```

**76 tests · 80% statement coverage** across all five testable modules
(`daemonClient`, `interceptor`, `notificationUI`, `sentinelHook`, `statusBar`).

---

## Manual scan examples

### Safe package

```bash
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"package_name":"lodash","project_path":".","ai_suggested":false}' \
  | python3 -m json.tool
```

Expected: `"decision": "ALLOW"`, `risk_score` near 0.

### Typosquatted package

```bash
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"package_name":"lodahs","project_path":".","ai_suggested":false}' \
  | python3 -m json.tool
```

Expected: `"decision": "WARN"`, flag `typosquat_detected`, `similar_to: "lodash"`.

### AI-hallucinated package

```bash
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"package_name":"totally-fake-pkg-xyz999","project_path":".","ai_suggested":true}' \
  | python3 -m json.tool
```

Expected: `"decision": "BLOCK"`, flag `package_not_found`, score ≥ 80.

### Trust bypass

```bash
# Add a package to the trust list
curl -s -X POST http://127.0.0.1:7355/api/v1/trust \
  -H "Content-Type: application/json" \
  -d '{"package_name":"my-internal-lib"}'

# Subsequent scans return ALLOW immediately (no pillar analysis)
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"package_name":"my-internal-lib","project_path":"."}'
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
| **Contextify** | 15% | Embeds existing project imports; cosine similarity to candidate description. Flags packages that are semantically unrelated to the project's tech stack. |
| **Sentinel** | 40% | NPM registry: package age, monthly downloads, maintainer count, repository presence. Levenshtein typosquat detection against top packages. Full hallucination check for AI-suggested packages. |
| **Shield** | 45% | Lifecycle script regex scan: `eval`, `curl`/`wget`, base64 decode, `process.env` exfiltration, crypto-miner strings, obfuscation. Prompt injection pattern scan on README and description. |
| **Aggregator** | — | `score = 0.15×contextify + 0.40×sentinel + 0.45×shield`. Maps to ALLOW (<40) / WARN (40–79) / BLOCK (≥80). Results cached in SQLite for 1 hour. |

---

## Decision thresholds

| Decision | Score range | Behaviour |
|---|---|---|
| `ALLOW` | 0–39 | Install proceeds; green notification in VS Code |
| `WARN` | 40–79 | Install proceeds with a dismissible warning dialog |
| `BLOCK` | 80–100 | Shim exits 1 (install aborted); VS Code shows blocking dialog |

Thresholds are configurable via `BLOCK_THRESHOLD` and `WARN_THRESHOLD` in `.env`.

---

## Threat coverage

| Attack vector | Pillar |
|---|---|
| Typosquatting (`lodasH`, `expres`) | Sentinel |
| AI hallucination (model invents a package name) | Sentinel (`ai_suggested`) |
| Malicious `postinstall` (curl, eval, env exfil) | Shield |
| Prompt injection in package README | Shield |
| Dependency confusion (unfamiliar package in established project) | Contextify + Sentinel |

See [docs/threat-model.md](docs/threat-model.md) for the full adversary model.

---

## Project structure

```
cidas/
├── daemon/                 Python FastAPI daemon
│   ├── pillars/            Four analysis pillars
│   │   ├── contextify.py   Embedding-based project context
│   │   ├── sentinel.py     Registry reputation & typosquat
│   │   ├── shield.py       Script scanning & injection detection
│   │   └── aggregator.py   Weighted scoring & verdict
│   ├── utils/              Shared utilities (embeddings, registry, logger)
│   ├── tests/              48 pytest tests (89% coverage)
│   ├── config.py           Pydantic settings from .env
│   ├── database.py         SQLite scan cache & trust list
│   ├── models.py           Shared Pydantic request/response models
│   ├── router.py           FastAPI endpoints (/scan /trust /cache /health)
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
│   ├── npm-shim.js         Transparent npm wrapper (Node.js)
│   ├── install-shim.sh     PATH injection installer
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
