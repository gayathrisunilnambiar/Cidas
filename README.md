# CIDAS — CI Dependency Analysis & Screening

A VS Code extension + local daemon that screens npm packages for malware, typosquatting, and AI hallucinations before they are installed.

```
npm install <pkg>
      │
      ▼
npm shim (intercept/)
      │ POST /scan
      ▼
Python daemon (localhost:7355)
  ├── Contextify   — project context match
  ├── Sentinel     — registry reputation + typosquat
  ├── Shield       — script scan + tarball AST + diff
  └── Aggregator   — ALLOW / WARN / BLOCK
      │
      ▼
VS Code extension — inline verdict + notification
```

## Why CIDAS exists alongside npm audit, Socket, and Snyk

npm audit only catches known CVEs after a vulnerability is reported. Socket.dev detects malicious install scripts before install but has no awareness of your project or of AI-suggested package names. npq runs pre-install heuristics but is stateless and context-blind. None of them address the three newest attack patterns.

| Capability | npm audit | Socket | npq | Snyk | CIDAS |
|---|---|---|---|---|---|
| Pre-install interception | ✗ | ✓ | ✓ | ✗ | ✓ |
| Lifecycle script scan | ✗ | ✓ | ✗ | ✗ | ✓ |
| Tarball AST file scan | ✗ | ✗ | ✗ | ✗ | ✓ |
| Typosquat detection | ✗ | ✓ | ✗ | ✗ | ✓ |
| Project context scoring | ✗ | ✗ | ✗ | ✗ | ✓ |
| AI suggestion provenance | ✗ | ✗ | ✗ | ✗ | ✓ |
| Hallucination guard | ✗ | ✗ | ✗ | ✗ | ✓ |
| Cross-version diff analysis | ✗ | ✗ | ✗ | ✗ | ✓ |
| Adversarial README detection | ✗ | ✗ | ✗ | ✗ | ✓ |
| Fully on-device | ✓ | ✗ | ✓ | ✗ | ✓ |
| VS Code integration | ✗ | ✗ | ✗ | ✓* | ✓ |
| Per-project policy file | ✗ | ✗ | ✗ | ✗ | ✓ |

*Snyk VS Code plugin surfaces post-install findings only.

### The five gaps CIDAS fills

1. **Project-context scoring** — No existing tool asks whether a package makes sense for your specific project. A crypto-mining library flagged identically whether it is being installed into a children's game or a financial trading system. CIDAS scores packages relative to your project's existing dependency fingerprint.
2. **AI suggestion provenance** — When Copilot or Cursor suggests a package name that does not exist, attackers can register it with malicious code. CIDAS monitors VS Code language model events and applies a stricter hallucination guard — download count, creation date, registry existence — to any AI-suggested package name. Human-typed packages use a lighter check.
3. **Cross-version differential analysis** — The event-stream attack (2018), ua-parser-js (2021), and node-ipc (2022) all followed the same pattern: a benign package's next version introduced a hidden payload. CIDAS diffs the AST capability sets of the current version against the previous release, flagging new dangerous imports, new process.env access, and new network calls that were absent before.
4. **Adversarial scanner manipulation** — LLM-based scanners can be primed to dismiss legitimate-looking flags by a crafted README. CIDAS uses a secondary local LLM (Ollama, on-device) to independently evaluate README content as data rather than instructions, resistant to prompt injection by design.
5. **Repository-committable policy** — Teams can commit a .cidas/policy.json to enforce project-specific rules: block lists, trust lists, minimum download thresholds, and Contextify weight overrides. Policy travels with the codebase and overrides global tool configuration.

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | 9+ |
| VS Code | 1.89+ |

> **Windows:** Run bash commands in Git Bash or WSL2. The daemon runs natively on Windows via PowerShell.

## Quickstart

### 1. Clone and configure
```bash
git clone <repo-url> cidas
cd cidas
cp .env.example .env
```
Defaults work out of the box for local testing.

### 2. Start the daemon

**macOS / Linux / WSL:**
```bash
bash scripts/start-daemon.sh
```
**Windows (PowerShell):**
```powershell
.\scripts\start-daemon.ps1
```
Verify:
```bash
curl http://127.0.0.1:7355/api/v1/health
# → {"status":"ok","version":"0.1.0"}
```

### 3. Install the VS Code extension
```bash
cd extension
npm install
npm run compile
```
Open the `cidas` folder in VS Code and press **F5**.
Check the status bar — it should show `$(shield) CIDAS ready`.

### 4. Install the npm shim

**macOS / Linux / WSL:**
```bash
bash intercept/install-shim.sh
source ~/.bashrc  # or source ~/.zshrc
```
**Windows (PowerShell):**
```powershell
.\intercept\install-shim.ps1
```
Verify:
```bash
which npm
# → /home/<user>/.cidas/npm  (Linux/macOS)
```

## Testing the extension

### Safe package (expect ALLOW)
```bash
TOKEN=$(cat ~/.cidas/daemon.token)
npm install lodash
# [CIDAS ALLOW] Package passed screening (risk score ~8/100)
```

### Typosquat (expect WARN)
```bash
npm install lodahs
# [CIDAS WARNING] typosquat_detected — similar to lodash
```

### AI-hallucinated package (expect BLOCK)
```bash
TOKEN=$(cat ~/.cidas/daemon.token)
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"totally-fake-pkg-xyz999",
       "project_path":".","ai_suggested":true}' \
  | python3 -m json.tool
# "decision": "BLOCK", risk_score >= 80
```

### Emergency bypass (if CIDAS blocks a known-safe package)
```bash
CIDAS_BYPASS=1 npm install <package>
```

## How decisions are made

Each scan produces a weighted score (0–100) across three pillars. Scores are combined and compared to two thresholds.

| Score | Decision | Behaviour |
|---|---|---|
| 0–39 | ALLOW | Silent pass |
| 40–79 | WARN | Warning dialog, install continues |
| 80–100 | BLOCK | Install aborted |

| Pillar | Weight | What it checks |
|---|---|---|
| Contextify | 30% | Semantic similarity to your project's existing dependencies |
| Sentinel | 35% | Registry reputation, package age, download count, typosquat detection, AI hallucination guard |
| Shield | 35% | Lifecycle scripts, tarball AST scan, prompt injection in README, cross-version capability diff |

## Trust list and policy

### Trusting a package permanently
```bash
TOKEN=$(cat ~/.cidas/daemon.token)
curl -s -X POST http://127.0.0.1:7355/api/v1/trust \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"my-internal-lib"}'
```

### Per-project policy file
Create `.cidas/policy.json` in your project root:
```json
{
  "version": 1,
  "block_list": ["known-bad-package"],
  "trust_list": ["my-internal-lib"],
  "warn_requires_confirmation": true
}
```
Policy is discovered by walking up ancestor directories.
See `docs/policy-engine.md` for the full schema.

## Running tests

```bash
# All tests (daemon + extension + shim)
bash scripts/run-tests.sh

# Daemon only
source daemon/.venv/bin/activate
pytest daemon/tests/ -v --cov=daemon

# Extension only (run from Windows or WSL with
# Linux-native node_modules)
cd extension && npx vitest run --coverage

# Shim only
cd intercept && npx jest --coverage
```

Current coverage: 357 daemon tests (91%), 99 extension tests (81%), 45 shim tests.

## Reproducing the evaluation results

The labelled-corpus evaluation, ablation study, threshold-sensitivity sweep,
and external baseline comparisons (npm audit, OSV-Scanner, Socket.dev,
GuardDog) all live in `daemon/eval/` — see
[`daemon/eval/README.md`](daemon/eval/README.md) for corpus provenance,
setup instructions per baseline tool, and how to run each script. Corpus
composition and version are recorded in `daemon/eval/corpus/corpus_metadata.json`;
per-record citations are in `daemon/eval/CORPUS_PROVENANCE.md`.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| BLOCK_THRESHOLD | 80 | Risk score that triggers BLOCK |
| WARN_THRESHOLD | 40 | Risk score that triggers WARN |
| CONTEXT_WEIGHT | 0.30 | Contextify pillar weight |
| SENTINEL_WEIGHT | 0.35 | Sentinel pillar weight |
| SHIELD_WEIGHT | 0.35 | Shield pillar weight |
| LLM_VERIFICATION_ENABLED | false | Enable Ollama-based README second pass |
| OLLAMA_HOST | http://localhost:11434 | Ollama server URL |
| OLLAMA_MODEL | phi3:mini | Local model to use |
| DISK_CHECK_ENABLED | true | Enable disk footprint analysis |

### Optional: Enable local LLM verification
```bash
# Install Ollama from https://ollama.com then:
ollama pull phi3:mini
# Set in .env:
LLM_VERIFICATION_ENABLED=true
```
If Ollama is not running, CIDAS falls back to regex-only injection detection automatically.

## API reference

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | /api/v1/health | None | Liveness check |
| POST | /api/v1/scan | Bearer | Screen a package |
| POST | /api/v1/trust | Bearer | Add to trust list |
| GET | /api/v1/trust/verify | Bearer | Audit trust list integrity |
| DELETE | /api/v1/cache | Bearer | Clear expired cache |
| POST | /api/v1/cache/invalidate | Bearer | Evict specific version |
| GET | /api/v1/audit | Bearer | Query scan log |
| GET | /api/v1/policy | Bearer | Resolve project policy |

Swagger UI: http://127.0.0.1:7355/docs

## Security properties

- **Fail-open** — daemon offline = ALLOW with warning, never blocks your workflow
- **Bearer token auth** — all mutating endpoints require a token stored at ~/.cidas/daemon.token (mode 0600)
- **HMAC trust integrity** — direct SQLite edits are detected and logged at CRITICAL level
- **Shim self-integrity** — SHA-256 hash verified on every invocation; tampered shim exits immediately
- **Tarball path-traversal guard** — extraction refuses entries that escape the temp directory
- **Audit log** — append-only JSONL at ~/.cidas/audit.log; all override events recorded

## Docs

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Policy engine](docs/policy-engine.md)
- [API reference](docs/api-reference.md)
