# CIDAS Architecture

## System overview

```
Developer workstation
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  Terminal                      VS Code                           │
│  ┌──────────────┐              ┌────────────────────────────────┐│
│  │ npm install  │              │ Extension (TypeScript)         ││
│  │   <pkg>      │              │  ┌──────────────────────────┐  ││
│  └──────┬───────┘              │  │ Interceptor              │  ││
│         │                      │  │ SentinelHook (AI detect) │  ││
│  ┌──────▼───────┐              │  │ StatusBarManager         │  ││
│  │ npm-shim.js  │              │  │ NotificationUI           │  ││
│  │ (intercept/) │              │  └──────────┬───────────────┘  ││
│  └──────┬───────┘              └─────────────│──────────────────┘│
│         │  HTTP POST /api/v1/scan            │                   │
│         └────────────────────────────────────┘                   │
│                              │                                   │
│              ┌───────────────▼──────────────────┐               │
│              │  CIDAS Daemon  (FastAPI/Uvicorn)  │               │
│              │  localhost:7355                   │               │
│              │                                   │               │
│              │  ┌──────────┐  ┌──────────────┐  │               │
│              │  │ SQLite   │  │ ChromaDB     │  │               │
│              │  │ cache    │  │ (embeddings) │  │               │
│              │  └──────────┘  └──────────────┘  │               │
│              │                                   │               │
│              │  Pillars (run in parallel):        │               │
│              │   Contextify ─ tree-sitter AST    │               │
│              │   Sentinel   ─ NPM registry       │               │
│              │   Shield     ─ script + injection  │               │
│              │   Aggregator ─ weighted scoring   │               │
│              └──────────────────────────────────┘               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
          │                      │
          ▼                      ▼
  registry.npmjs.org    api.npmjs.org/downloads
```

## Component responsibilities

### npm-shim.js
Transparent `npm` replacement installed earlier on `PATH`.  Intercepts
`npm install <pkg>` calls, POSTs each package to `/api/v1/scan`, and exits 1
on `BLOCK`.  Fails open if the daemon is unreachable.

### VS Code Extension
- **DaemonClient** — typed HTTP client; returns safe ALLOW on daemon offline.
- **SentinelHook** — tracks AI-suggested packages via terminal data events.
- **Interceptor** — `FileSystemWatcher` on `package.json` diffs; scans new deps.
- **StatusBarManager** — colour-coded status bar with auto-reset.
- **NotificationUI** — warn/block dialogs and a Webview details panel.

### CIDAS Daemon
FastAPI app on port 7355. Request timing via HTTP middleware. All three
analysis pillars run concurrently with `asyncio.gather` and results are
cached in SQLite for 1 hour.

### Pillar: Contextify (weight 15 %)
1. Parse `package.json` + walk JS/TS source files with **tree-sitter**.
2. Embed the set of existing imports using **sentence-transformers**.
3. Embed the candidate package description from the npm registry.
4. Cosine similarity → inverted risk score.

### Pillar: Sentinel (weight 40 %)
For AI-suggested packages only (skips human-typed installs):
- Registry existence check (404 → high risk)
- Package age and download count signals
- Levenshtein edit-distance against the top-500 npm packages for typosquat detection

### Pillar: Shield (weight 45 %)
1. Fetch lifecycle scripts (`preinstall`, `postinstall`, `prepare`) from registry.
2. Regex pattern scan: `eval`, `curl`/`wget`, base64 decode, env-var exfiltration,
   obfuscated hex strings, crypto-miner strings.
3. Prompt injection pattern scan over package README and description.
4. *(TODO phase-2)* Secondary LLM verification pass.

### Aggregator
```
risk_score = 0.15 × contextify + 0.40 × sentinel + 0.45 × shield
```
- `risk_score < 40`  → `ALLOW`
- `40 ≤ risk_score < 80` → `WARN`
- `risk_score ≥ 80`  → `BLOCK`

## Data flow — `npm install some-pkg`

1. Shim intercepts, sends `POST /api/v1/scan {package_name: "some-pkg", project_path: …}`.
2. Router checks trust cache → miss.
3. Router checks SQLite cache → miss (first time).
4. `asyncio.gather(contextify.score, sentinel.score, shield.score)`.
5. `Aggregator.aggregate()` → `(risk_score, explanation)`.
6. Router maps score → decision, builds `ScanResponse`, stores in SQLite.
7. Shim receives response: ALLOW → continues; BLOCK → exits 1.
8. VS Code extension independently shows a notification.
