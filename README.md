# CIDAS — CI Dependency Analysis & Screening

A VS Code extension paired with a local Python daemon that screens npm packages
**before** they are installed, catching typosquatting, malware, and suspicious
provenance in real time.

## Architecture overview

```
npm install <pkg>
      │
      ▼
 npm-shim.js          (intercept/npm-shim.js — wraps the real npm binary)
      │
      ▼
 CIDAS Daemon         (Python · FastAPI · localhost:7979)
  ├─ Contextify       pillar 1 — AST-based project context extraction
  ├─ Sentinel         pillar 2 — NPM registry metadata & reputation checks
  ├─ Shield           pillar 3 — vulnerability & malicious-pattern detection
  └─ Aggregator       pillar 4 — weighted risk score & final verdict
      │
      ▼
 VS Code Extension    (TypeScript)
  ├─ Status bar       live risk indicator
  └─ Notification UI  block / warn / allow dialogs
```

## Quick start

### 1. Install daemon dependencies

```bash
cd cidas/daemon
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — at minimum set DAEMON_SECRET
```

### 3. Start the daemon

```bash
bash scripts/start-daemon.sh
```

### 4. Install the VS Code extension (dev mode)

```bash
cd extension
npm install
npm run compile
# Open VS Code → Run Extension (F5)
```

### 5. Install the npm shim

```bash
bash intercept/install-shim.sh
```

Now every `npm install` in your terminal is screened automatically.

## Running tests

```bash
bash scripts/run-tests.sh
```

## Pillars

| Pillar | Role |
|---|---|
| **Contextify** | Parses project source with tree-sitter to understand what APIs/patterns are already in use, building an embedding-based context vector. |
| **Sentinel** | Queries the NPM registry for metadata signals: age, download counts, maintainer count, publish frequency, README quality. |
| **Shield** | Checks OSV for known CVEs; scans packed tarball contents for known-malicious patterns (network calls in install scripts, obfuscated code). |
| **Aggregator** | Combines pillar scores into a single 0–100 risk score and emits a `BLOCK` / `WARN` / `ALLOW` verdict. |

## Docs

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [API reference](docs/api-reference.md)
