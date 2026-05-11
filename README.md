# CIDAS — CI Dependency Analysis & Screening

A VS Code extension paired with a local Python daemon that screens npm packages
**before** they are installed, catching typosquatting, malware, AI-hallucinated
packages, and prompt injection in real time. Distribution is a transparent
`npm` shim, with team-wide policy carried in the repo via `.cidas/policy.json`.

---

## Project structure

```
cidas/
├── daemon/                 Python FastAPI daemon
│   ├── pillars/            Four analysis pillars
│   │   ├── contextify.py   Embedding-based project context
│   │   ├── sentinel.py     Registry reputation & typosquat
│   │   ├── shield.py       Script scanning & tarball file scan
│   │   └── aggregator.py   Weighted scoring & verdict
│   ├── utils/              Shared utilities
│   │   ├── audit_log.py    Append-only JSONL audit log with rotation
│   │   ├── policy.py       .cidas/policy.json discovery + validation
│   │   ├── offline_cache.py name@version offline-allow cache
│   │   ├── npm_registry.py Registry lookups + tarball download
│   │   ├── embeddings.py   Sentence embedding helpers
│   │   └── logger.py       Structured logging
│   ├── tests/              185 pytest tests
│   ├── auth.py             Bearer token generation & verification
│   ├── cli.py              `python -m daemon.cli audit ...`
│   ├── config.py           Pydantic settings from .env
│   ├── database.py         SQLite scan cache (name@version) & HMAC trust list
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
└── .cidas/
    └── policy.schema.json  JSON Schema for project policy files
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | 9+ |
| VS Code | 1.89+ |

> **Windows users:** run all `bash` commands inside **WSL 2** (not WSL 1 — WSL 1 cannot invoke `node.exe` correctly). To check: `wsl --list --verbose`. To upgrade: `wsl --set-version Ubuntu-22.04 2`.

> **WSL npm PATH:** after installing Node.js inside WSL, the Windows npm at `/mnt/c//npm` may still shadow the native one. Fix with `export PATH=/usr/bin:$PATH` or add it permanently to `~/.bashrc`.

> **First scan is slow:** on first run the daemon downloads the `all-MiniLM-L6-v2` embedding model (~90 MB) from HuggingFace. Expect 1–3 minutes before the first response. All subsequent scans are fast. To avoid HuggingFace rate-limit warnings, set `HF_TOKEN` in your `.env` (optional).

---

## Clone & install

```bash
git clone <repo-url> cidas
cd cidas

# 1. Daemon
cp .env.example .env
bash scripts/start-daemon.sh                # creates daemon/.venv, installs deps, starts on :7355
curl http://127.0.0.1:7355/api/v1/health    # → {"status":"ok",...}

# 2. VS Code extension
cd extension && npm install && npm run compile && cd ..
# In VS Code: open the cidas folder, press F5 to launch the extension host.

# 3. npm shim
bash intercept/install-shim.sh
exec bash                                   # reload PATH
which npm                                   # → ~/.cidas/npm
```

To remove: `bash intercept/uninstall-shim.sh && kill $(cat .cidas.pid)`.

---

## Run automated tests

```bash
# Daemon (185 tests)
source daemon/.venv/bin/activate
pytest daemon/tests/ -v --cov=daemon --cov-report=term-missing

# Extension (~80 tests)
cd extension && npx vitest run --coverage --reporter=verbose && cd ..

# npm shim (~50 tests)
cd intercept && npm test && cd ..

# All at once
bash scripts/run-tests.sh
```

---

## Manual functionality test

The remainder of this document is a step-by-step walkthrough to verify every
feature works end-to-end. Run from the repo root.

### 0. Prepare a session

```bash
source daemon/.venv/bin/activate
bash scripts/start-daemon.sh      # waits until /api/v1/health responds (up to 30 s)
export TOKEN=$(cat ~/.cidas/daemon.token)
```

> The script now polls `/api/v1/health` and prints `[CIDAS] Daemon is ready.` before returning — no need to sleep or retry manually.

### 1. Smoke test — three verdicts

```bash
# ALLOW/WARN — popular package (verdict depends on project context)
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"lodash","project_path":"'"$PWD"'"}' | python3 -m json.tool
# Expect: decision = ALLOW or WARN, risk_score ≤ 15
# Note: if the project has no JS dependencies, contextify flags lodash as
# "unfamiliar_in_mature_project" (score ~9) → WARN. This is correct behaviour.

# WARN — typosquat
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"lodahs","project_path":"'"$PWD"'"}' | python3 -m json.tool
# Expect: decision = WARN, flag "typosquat_detected", similar_to "lodash"

# BLOCK — AI-hallucinated package
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"totally-fake-pkg-xyz999","project_path":"'"$PWD"'","ai_suggested":true}' | python3 -m json.tool
# Expect: decision = BLOCK, flag "package_not_found", score ≥ 80
```

### 2. Auth gate

```bash
# No token → 401
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  http://127.0.0.1:7355/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"package_name":"lodash","project_path":"."}'
# Expect: 401

# Wrong token → 401
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer wrong" -H "Content-Type: application/json" \
  -d '{"package_name":"lodash","project_path":"."}'
# Expect: 401

# Health stays open
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:7355/api/v1/health
# Expect: 200
```

### 3. Trust list (per-machine, HMAC-protected)

```bash
# Add a package to the local trust list
curl -s -X POST http://127.0.0.1:7355/api/v1/trust \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"my-internal-lib"}'

# Subsequent scan should ALLOW immediately with flag "trusted"
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"my-internal-lib","project_path":"'"$PWD"'"}' | python3 -m json.tool

# Audit the HMAC integrity of every trust-list row
curl -s http://127.0.0.1:7355/api/v1/trust/verify \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# Expect: tampered = 0

# Tamper test: corrupt the SQLite trust row directly
# (sqlite3 CLI may not be installed; use the Python one-liner instead)
python3 -c "import sqlite3; c=sqlite3.connect('.cidas_cache.db'); c.execute(\"UPDATE trust_cache SET trust_list_mac='deadbeef' WHERE package_name='my-internal-lib'\"); c.commit(); c.close()"
curl -s http://127.0.0.1:7355/api/v1/trust/verify \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# Expect: tampered = 1, tampered_packages = ["my-internal-lib"]
```

### 4. Project policy (`.cidas/policy.json`)

```bash
mkdir -p /tmp/proj/.cidas
cat > /tmp/proj/.cidas/policy.json <<'EOF'
{
  "version": 1,
  "block_list": ["bad-pkg"],
  "trust_list": ["our-internal-lib"],
  "min_monthly_downloads": 10000,
  "require_repository_link": true,
  "warn_requires_confirmation": true
}
EOF

# View resolved policy
curl -s "http://127.0.0.1:7355/api/v1/policy?project_path=/tmp/proj" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# block_list overrides everything
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"bad-pkg","project_path":"/tmp/proj"}' | python3 -m json.tool
# Expect: BLOCK, flag "policy_block", policy_file set, requires_confirmation = false
# Note: warn_requires_confirmation applies to WARN verdicts only; BLOCK always exits immediately.

# trust_list bypasses pillars
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"our-internal-lib","project_path":"/tmp/proj"}' | python3 -m json.tool
# Expect: ALLOW, flag "policy_trust"

# Validator rejects unknown fields
echo '{"version":1,"blocklist":["typo-key"]}' > /tmp/proj/.cidas/policy.json
curl -s "http://127.0.0.1:7355/api/v1/policy?project_path=/tmp/proj" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# Expect: policy_file = null (invalid file ignored)
```

### 5. Audit log + CLI

```bash
# Query via REST (auth required)
curl -s "http://127.0.0.1:7355/api/v1/audit?last=10&verdict=BLOCK" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
curl -s "http://127.0.0.1:7355/api/v1/audit?package=lodash" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Query via CLI
python -m daemon.cli audit --last 5
python -m daemon.cli audit --verdict BLOCK
python -m daemon.cli audit --package lodash
python -m daemon.cli audit --since 2026-05-01T00:00:00+00:00

# Record a manual override event (what the VS Code extension does)
curl -s -X POST http://127.0.0.1:7355/api/v1/audit/override \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"lodahs","verdict_was":"WARN"}'

# Inspect rotation files (audit.log rotates at 10 MB → .1 .2 .3)
ls -lh ~/.cidas/audit.log*
```

### 6. Cache + invalidation

```bash
# Two scans → second is a cache hit
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"axios","version":"1.6.0","project_path":"."}' >/dev/null
curl -s -X POST http://127.0.0.1:7355/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"axios","version":"1.6.0","project_path":"."}' >/dev/null
python -m daemon.cli audit --package axios --last 2
# Expect: two records, second has "cached": true

# Emergency invalidation
curl -s -X POST http://127.0.0.1:7355/api/v1/cache/invalidate \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package_name":"axios","version":"*"}'
```

### 7. npm shim

> **WSL only:** ensure the native npm is on your PATH before testing the shim.
> Run `which npm` — if it shows `/mnt/c//npm` (Windows), run `export PATH=/usr/bin:$PATH` first.

```bash
mkdir -p /tmp/shim-test && cd /tmp/shim-test && npm init -y

npm install lodash      # → [CIDAS ALLOW] ...
npm install lodahs      # → [CIDAS WARNING] typosquat_detected
CIDAS_BYPASS=1 npm install some-pkg
                        # → [CIDAS BYPASS] entry appended to ~/.cidas/audit.log

cd /mnt/c/Gayathri/Cidas
```

#### 7a. Shim integrity self-check

```bash
echo "// tampered" >> ~/.cidas/npm-shim.js
npm install anything
# Expect: red "Shim integrity check FAILED", exit 1

bash intercept/sign-shim.sh   # re-sign to recover
npm --version
```

#### 7b. WARN confirmation prompt

```bash
echo '{"warn_requires_confirmation": true}' > ~/.cidas/config.json
cd /tmp/shim-test
npm install lodahs
# Expect prompt: [CIDAS] Type 'proceed' to continue or press Ctrl-C to cancel:
#   "no" → exits 1
#   "proceed" → continues
#   Ctrl-C → exits 1

# Non-interactive bypasses the prompt
echo "" | npm install lodahs   # no prompt, proceeds

# Project policy can force the prompt even without local config
rm ~/.cidas/config.json
mkdir -p /tmp/shim-test/.cidas
echo '{"version":1,"warn_requires_confirmation":true}' \
  > /tmp/shim-test/.cidas/policy.json
npm install lodahs              # prompts again

cd /mnt/c/Gayathri/Cidas
```

### 8. VS Code extension

1. Open the repo in VS Code, press **F5** to launch the extension host.
2. Status bar reads `CIDAS ready`.
3. `Ctrl-Shift-P` → **CIDAS: Scan Package** → enter `lodahs`.
4. WARN dialog appears with buttons in this order:
   1. **Show Details** (primary)
   2. **Proceed Anyway**
   3. **Cancel install**
5. Click **Show Details** → details panel opens (pillar table + project policy file path).
6. Click **Cancel install** → info popup notes the cancel intent; an event with
   `event: "user_cancel_intent"` lands in `~/.cidas/audit.log`.
7. Click **Proceed Anyway** → an event with `event: "user_override"` lands.
8. **Auto-scan**: open a `package.json`, add `"lodahs": "*"` to dependencies, save —
   the WARN dialog should fire automatically.

---

## Cleanup

```bash
bash intercept/uninstall-shim.sh
kill $(cat .cidas.pid)
rm -f ~/.cidas/config.json
rm -rf /tmp/proj /tmp/shim-test
```
