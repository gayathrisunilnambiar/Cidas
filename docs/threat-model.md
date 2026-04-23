# CIDAS Threat Model

## Scope

CIDAS defends a developer workstation from **supply-chain attacks delivered
via npm packages** at install time. It does not replace production runtime
security tooling (SCA scanners, WAFs, SAST).

## Assets

| Asset | Value |
|---|---|
| Developer credentials (git tokens, cloud keys) | High |
| Source code | High |
| CI/CD pipeline configuration | High |
| Installed npm packages | Medium |

## Threat actors

| Actor | Motivation | Capability |
|---|---|---|
| Typosquatter | Financial gain via credential theft | Low–Medium |
| Compromised maintainer | Supply-chain sabotage | Medium–High |
| Nation-state / APT | Targeted espionage | High |

## Threat scenarios

### T1 — Typosquatting
Attacker publishes `lodasH` (1-char difference from `lodash`). Developer
mistype triggers a malicious install.

**CIDAS mitigation:** Sentinel pillar runs Levenshtein distance check against
the top 20 packages. Distance ≤ 2 → +50 risk points.

### T2 — Malicious install script
Package includes a `postinstall` script that exfiltrates `process.env` variables
containing API keys.

**CIDAS mitigation:** Shield pillar pattern-matches lifecycle scripts for
`process.env.*KEY|TOKEN|SECRET`, network calls, and `eval`. High-confidence
match → large risk contribution.

### T3 — New / abandoned package with CVEs
Developer installs an old pinned version that has unpatched CVEs.

**CIDAS mitigation:** Shield pillar queries OSV for every requested package +
version. Each CVE adds 25 points to the risk score.

### T4 — Dependency confusion
Attacker publishes a public package with the same name as an internal private
package, exploiting npm's resolution order.

**CIDAS mitigation:** Contextify pillar notes that the package name has no
match in existing project imports (unfamiliar pattern signal). Sentinel notes
the package is new and has low downloads. Combined score is likely WARN.
CIDAS does **not** fully block this class — teams should also use `--prefer-offline`
or scoped package configurations.

### T5 — Daemon MITM / API abuse
Attacker on the local machine intercepts traffic between the shim and daemon.

**CIDAS mitigation:** Traffic is localhost-only (127.0.0.1). Shared secret
header (`X-CIDAS-Secret`) prevents requests from other processes. HTTPS is
not strictly necessary on loopback but can be added via a self-signed cert.

## Limitations

- CIDAS screens at **install time only**. Packages already in `node_modules`
  are not re-scanned unless the cache is cleared.
- The typosquat list covers only 20 popular packages; expand `_POPULAR_PACKAGES`
  in `sentinel.py` as needed.
- Obfuscated malware that does not match the pattern list in Shield will not be
  caught heuristically — OSV remains the primary defence in that case.
- CIDAS can be bypassed by setting `CIDAS_BYPASS=1` in the environment; this
  is intentional to avoid blocking critical CI pipelines, but should be audited.

## Residual risk

After CIDAS mitigations, residual risk is highest for:
- Novel malware with clean OSV records and no suspicious script patterns
- Packages installed via CI where the shim is not present
- Packages injected via lock-file tampering (CIDAS does not validate lockfiles)
