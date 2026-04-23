# CIDAS Threat Model

## Adversary model

| Capability level | Description |
|---|---|
| **Registry write** | Attacker can publish packages to the npm registry |
| **Metadata control** | Attacker controls package description, README, scripts |
| **LLM API access** | Attacker can craft inputs to AI coding assistants |

CIDAS is scoped to the **developer workstation** — it does not defend running
production systems or CI pipelines where the shim is not installed.

## Assets

| Asset | Value |
|---|---|
| Developer credentials (git tokens, cloud API keys) | Critical |
| Source code and IP | High |
| CI/CD pipeline configuration | High |
| Developer machine environment | Medium |

## Attack vector categories

### AV-1 — Typosquatting
Attacker publishes `lodasH` (1-char drift from `lodash`). A mistyped install
silently executes a malicious `postinstall`.

**Coverage:** Sentinel pillar (Levenshtein ≤ 2 → +40 risk).
**Residual risk:** Packages beyond the top-500 list are not checked.

### AV-2 — Dependency hijack / abandoned package
A formerly safe package is taken over by a malicious actor, or a package with
known CVEs is pinned without version bumps.

**Coverage:** Shield pillar queries OSV; Sentinel checks package age and
maintainer count.

### AV-3 — AI hallucination exploit
Developer asks Copilot/Claude to suggest a package; the model hallucinates a
plausible-but-nonexistent name. Attacker registers that name first.

**Coverage:** SentinelHook tags packages pasted from AI responses.  Sentinel
pillar runs a full registry existence + download-count check only for
`ai_suggested=true` packages.

### AV-4 — Malicious install script
Package includes a `postinstall` that phones home, exfiltrates env vars, or
downloads a second-stage payload.

**Coverage:** Shield pillar pattern-scans lifecycle scripts for `curl`, `eval`,
base64 decode, `process.env.*TOKEN`, obfuscated hex strings.

### AV-5 — Adversarial scanner attack (prompt injection in README)
Attacker embeds "ignore previous instructions" style text in the package
README/description, hoping to manipulate AI-assisted code review or CIDAS's
future LLM secondary verification pass.

**Coverage:** Shield pillar `detect_injection_patterns()` regex scan flags
known injection phrases.  Full LLM-based secondary verification is planned for
phase-2 (`TODO(phase-2): secondary_verification`).

## Pillar coverage matrix

| Attack vector | Contextify | Sentinel | Shield |
|---|:---:|:---:|:---:|
| Typosquatting | — | ✓ | — |
| Dependency hijack / CVE | — | ✓ | ✓ |
| AI hallucination exploit | — | ✓ (ai_suggested) | — |
| Malicious install script | — | — | ✓ |
| Prompt injection in metadata | — | — | ✓ |
| Dependency confusion | ✓ (unfamiliar) | ✓ (new/low-dl) | — |

## Explicit out-of-scope items

- Packages already installed in `node_modules` (scan-on-install only).
- Lock-file tampering (CIDAS does not validate `package-lock.json`).
- CI pipelines where the npm shim is not installed.
- Runtime behaviour of installed packages.
- Transitive (indirect) dependencies.
- Windows-native `cmd.exe` / PowerShell shim (shim is bash/node only).

## Trust bypass

`CIDAS_BYPASS=1` (shim) and `/api/v1/trust` (daemon) provide escape hatches
for emergency situations.  Both should be audited in CI policy.
