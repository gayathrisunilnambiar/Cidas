# CIDAS Threat Model

## Adversary model

| Capability level | Description |
|---|---|
| **Registry write** | Attacker can publish packages to the npm registry |
| **Metadata control** | Attacker controls package description, README, scripts |
| **LLM API access** | Attacker can craft inputs to AI coding assistants |
| **Supply-chain position** | Attacker can take over an existing package maintainer account |

CIDAS is scoped to the **developer workstation** — it does not defend running production systems. The npm shim must be installed for terminal protection; the VS Code extension must be running for editor protection.

## Assets

| Asset | Value |
|---|---|
| Developer credentials (git tokens, cloud API keys) | Critical |
| Source code and IP | High |
| CI/CD pipeline configuration | High |
| Developer machine environment | Medium |

## Attack vector categories

### AV-1 — Typosquatting
Attacker publishes `lodasH` (1-char drift from `lodash`). A mistyped `npm install` silently executes a malicious `postinstall`.

**Coverage:** Sentinel pillar — Levenshtein distance ≤ 2 against a bundled top-50 list flags `typosquat_detected` and sets Sentinel score to 100. Runs for all packages regardless of `ai_suggested`.

**Residual risk:** Packages outside the bundled list are not checked. The list covers common attack targets (lodash, react, express, axios, etc.) but not the full npm corpus.

---

### AV-2 — Dependency hijack / abandoned package
A formerly safe package is taken over by a malicious actor who publishes a new version with malicious install scripts.

**Coverage:** Shield pillar pattern-scans lifecycle scripts on every install. Cross-version diff (AV-6 below) also catches this by flagging capability changes introduced in the new version.

---

### AV-3 — AI hallucination exploit
Developer asks Copilot/Cursor to suggest a package; the model hallucinates a plausible-but-nonexistent name. Attacker registers that name first with malicious code.

**Coverage:** SentinelHook (VS Code extension) tags packages typed from AI chat responses. Sentinel pillar runs a full hallucination-risk analysis for `ai_suggested=true` packages: registry existence check (404 → score ≥ 85, always BLOCKed), package age, download count, repository presence. Human-typed packages receive a lighter check.

---

### AV-4 — Malicious install script
Package includes a `postinstall` that phones home, exfiltrates env vars, or downloads a second-stage payload.

**Coverage:** Shield pillar pattern-scans `preinstall`, `install`, `postinstall`, and `prepare` lifecycle scripts for: `curl`/`wget`/`fetch`, `eval`, base64 decode, `process.env.*TOKEN/SECRET/KEY/PASS` (case-insensitive), obfuscated hex strings, and known crypto-miner strings. Tarball file scan applies the same patterns to extracted JS files (up to 50 files, 0.6× weight to reduce false positives from minified bundles).

---

### AV-5 — Adversarial scanner attack (prompt injection in README)
Attacker embeds "ignore previous instructions" style text in the package README or description, hoping to prime AI-assisted review tools or LLM-based scanners into dismissing legitimate flags.

**Coverage (two layers):**
1. **Primary:** Shield `detect_injection_patterns()` regex scan flags known injection phrases in README/description. No LLM involved, immune to paraphrasing.
2. **Secondary (optional):** When `LLM_VERIFICATION_ENABLED=true` and the primary scan already has signal, Shield forwards the README to a local Ollama instance (`phi3:mini` by default). The README is passed as **data** in the user message, never as instructions — the system prompt explicitly instructs the model to treat the content as untrusted input. Falls back silently if Ollama is unreachable; the primary regex score is used alone.

**Residual risk:** Paraphrased injection phrases not covered by the regex list may evade the primary scan when LLM verification is disabled.

---

### AV-6 — Cross-version differential attack (supply-chain backdoor)
A benign, widely-used package receives a new version from a compromised maintainer. The new version is structurally similar to prior releases but introduces hidden `process.env` exfiltration, a new network call, or a dangerous new import not present before (event-stream 2018, ua-parser-js 2021, node-ipc 2022 all followed this pattern).

**Coverage:** Shield pillar `diff_analyzer` compares AST capability sets between the candidate version and the previous published release. Newly-introduced capabilities — `process.env` access, network calls (`fetch`/`http`/`axios`), `child_process` usage, `eval` — that were absent in the prior version are flagged as `new_dangerous_capability` and contribute to the Shield score.

**Residual risk:** First-ever published packages have no prior version to diff against; this check is silent for version `1.0.0`.

---

## Pillar coverage matrix

| Attack vector | Contextify | Sentinel | Shield |
|---|:---:|:---:|:---:|
| Typosquatting | — | ✓ | — |
| Dependency hijack / new-version backdoor | — | — | ✓ (script + diff) |
| AI hallucination exploit | — | ✓ (ai_suggested) | — |
| Malicious install script | — | — | ✓ (script scan) |
| Tarball-embedded payload | — | — | ✓ (file scan) |
| Prompt injection in metadata | — | — | ✓ (regex + Ollama) |
| Dependency confusion (internal pkg name) | ✓ (unfamiliar) | ✓ (low-dl, new) | — |
| Cross-version capability diff | — | — | ✓ (diff_analyzer) |

## Explicit out-of-scope items

- Packages already installed in `node_modules` (scan-on-install only).
- Lock-file tampering — CIDAS does not validate `package-lock.json`.
- CI pipelines where neither the npm shim nor the VS Code extension is installed.
- Runtime behaviour of installed packages.
- Transitive (indirect) dependencies when `scan_transitive=false` (the default).

## Trust bypass

`CIDAS_BYPASS=1` (shim) and `POST /api/v1/trust` (daemon) are escape hatches for known-safe packages. Both events are appended to `~/.cidas/audit.log`. Security leads can set `bypass_disabled: true` in `~/.cidas/config.json` to prevent `CIDAS_BYPASS=1` from working; this is recommended in CI environments.
