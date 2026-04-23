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
│  └──────┬───────┘              │  │ PackageJsonInterceptor   │  ││
│         │                      │  │ SentinelHook             │  ││
│  ┌──────▼───────┐              │  │ StatusBar / NotificationUI│  ││
│  │ npm-shim.js  │              │  └──────────┬───────────────┘  ││
│  │ (intercept/) │              └─────────────│──────────────────┘│
│  └──────┬───────┘                            │                   │
│         │   HTTP POST /api/v1/screen         │                   │
│         └────────────────────────────────────┘                   │
│                              │                                   │
│              ┌───────────────▼──────────────────┐               │
│              │  CIDAS Daemon  (FastAPI/Uvicorn)  │               │
│              │  localhost:7979                   │               │
│              │                                   │               │
│              │  ┌──────────┐  ┌──────────────┐  │               │
│              │  │SQLite    │  │ChromaDB      │  │               │
│              │  │cache     │  │(embeddings)  │  │               │
│              │  └──────────┘  └──────────────┘  │               │
│              │                                   │               │
│              │  Pillars:                         │               │
│              │   Contextify ─ tree-sitter AST    │               │
│              │   Sentinel   ─ NPM registry       │               │
│              │   Shield     ─ OSV + script scan  │               │
│              │   Aggregator ─ weighted scoring   │               │
│              └──────────────────────────────────┘               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
  registry.npmjs.org     api.osv.dev
```

## Component responsibilities

### npm-shim.js
Transparent wrapper installed ahead of the real npm binary on `PATH`.
Intercepts `npm install <pkg>` calls, POSTs each package name to the daemon,
and either passes through or exits non-zero based on the verdict.

### VS Code Extension
Provides the developer-facing UX:
- **PackageJsonInterceptor** — watches `package.json` file changes and
  screens newly added dependencies.
- **SentinelHook** — executes a screening call and routes to the correct
  notification handler based on the verdict.
- **StatusBar** — live per-verdict colour indicator.
- **NotificationUI** — modal/toast dialogs with a drill-down details panel.

### CIDAS Daemon
FastAPI app serving a single REST endpoint (`POST /api/v1/screen`).  
Runs all three analysis pillars concurrently with `asyncio.gather`, caches
results in SQLite, and returns a structured `ScreenResponse`.

### Pillar: Contextify
Uses **tree-sitter-javascript** to parse the project source tree and extract
all `import`/`require` specifiers. Embeds them with **sentence-transformers**
(all-MiniLM-L6-v2) and computes maximum cosine similarity against the
candidate package name. Low similarity in a mature project is a mild risk
signal.

### Pillar: Sentinel
Queries the NPM registry for package metadata and scores based on:
- Age (< 7 days = +40 risk)
- Weekly download count
- Maintainer count
- README quality
- Repository presence
- Levenshtein-distance typosquat detection against the top 20 packages

### Pillar: Shield
1. Queries **OSV** for known CVEs (each vuln adds 25 points, capped at 100).
2. Downloads package.json for the target version and pattern-matches lifecycle
   scripts for network calls, `eval`, base64 decoding, env-var exfiltration,
   child process execution, and crypto-miner hints.

### Aggregator
Combines scores with fixed weights:

| Pillar      | Weight |
|-------------|--------|
| Contextify  | 15 %   |
| Sentinel    | 40 %   |
| Shield      | 45 %   |

Final verdict:
- `≥ 80` → **BLOCK**
- `≥ 40` → **WARN**
- `< 40` → **ALLOW**

## Data flow for a single `npm install axios`

1. `npm-shim.js` intercepts, sends `POST /api/v1/screen` with `{package_name: "axios"}`.
2. Daemon checks SQLite cache → miss.
3. `asyncio.gather(contextify, sentinel, shield)` runs in parallel.
4. Aggregator weights scores → final verdict.
5. Result cached in SQLite for 1 hour.
6. Response returned to shim; extension also receives the response via the
   daemon client if the VS Code window is open.
7. Shim either continues (`npm install` spawned) or exits 1 (BLOCK).
