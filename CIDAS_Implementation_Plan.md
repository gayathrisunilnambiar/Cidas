# CIDAS Implementation Plan — Historical-Version Resolution & Shield Silent-Substitution Fix

**Context for this plan:** Investigation into the 15 undetected new-corpus records (worm/CI-compromise packages: `@ctrl/tinycolor` family, TanStack pipeline-compromise chain, `chalk`/`debug`/`axios` 2025 account-takeovers) found two distinct, previously undiagnosed bugs, not a structural limitation. The paper currently attributes this detection gap to npm's security purge destroying the historical version needed for cross-version diffing — that explanation is now confirmed false for all 15 records checked. This plan fixes the actual root causes and re-derives every downstream number and claim that depended on the incorrect assumption.

**Why this matters more than a typical bug fix:** Several things already written (or drafted) about these packages were built on Shield silently scanning the wrong artifact — the current clean `latest` version, not the compromised one. That means claims like "Shield's cross-version diff would catch the TanStack capability change" (in the threat-campaign walkthrough) and "0.0 recall due to purge-driven blind spot" (in the original 17-record finding) were never actually tested against real data. This plan replaces both with genuine, verified results before either goes into the manuscript.

---

## Step 1 — Fix `get_previous_version`'s exact-match lookup

**Problem:** `get_previous_version(name, current_version)` in `npm_registry.py` looks for `current_version` inside an already-filtered list of resolvable versions, then walks backward from that position. Since npm's security purge always removes the malicious version itself, `current_version` never appears in the filtered list, so the lookup returns `None` unconditionally — regardless of how much valid predecessor history sits right next to the gap. This was confirmed live for all 15 affected records (`get_previous_version_result: null`, `diff_ran: False` uniformly), even though a resolvable predecessor exists for every single one.

**Fix approach:** Change the lookup to work from version *ordering*, not exact match. Given the full (unfiltered) version list for a package, locate where `current_version` would sit in semver order even though it's absent from the resolvable list, then walk backward from that position to the nearest version that *is* resolvable. This requires the function to reason about the purged version's position relative to its neighbors rather than requiring it to be present in the list it's searching.

**Scope decision to make explicitly:** decide how far back the walk is allowed to go before giving up and returning "no resolvable predecessor found." An unbounded walk could, in principle, diff against a version many releases older than intended if a long run of versions were purged. A sensible default is worth stating in code comments and in the paper's methodology section (e.g., "walks back up to N versions before treating the package as undiffable"), so the limitation is documented rather than silent.

**Validation:** re-run the historical-version lookup against all 15 previously-null records and confirm each now resolves to the correct predecessor already identified in the investigation (e.g., `axios@1.14.1` → `axios@1.14.0`, `@tanstack/react-router@1.169.5` → `1.169.2`). This is a direct, checkable fix — the correct predecessor for each of the 15 is already known from the investigation, so this isn't exploratory, it's confirmatory.

---

## Step 2 — Fix Shield's silent version substitution

**Problem:** When `Shield.score()` cannot resolve the requested version, it silently substitutes `dist-tags.latest` and proceeds to scan that instead — with nothing in the response indicating a substitution occurred. This was confirmed directly: requests for `axios@1.14.1`, `chalk@5.6.1`, `debug@4.4.2`, and `@ctrl/tinycolor@4.1.1` all actually scanned newer, clean, unrelated versions (`axios-1.18.1.tgz`, `chalk-5.6.2.tgz`, `debug-4.4.3.tgz`, `tinycolor-4.2.0.tgz`). Every previously-reported "Shield signal" for these specific records — including flags like `base64_decode`, `network_in_install`, `child_process_exec` — was very likely triggered by ordinary, legitimate code in the current clean package (an HTTP library doing base64 encoding and network calls is not evidence of anything), not by the actual compromise.

**Why this is more serious than Step 1:** Step 1 is a missing capability (couldn't find the predecessor). This is a false signal (found *something*, scored it, and returned a verdict without disclosing that the something wasn't what was asked for). Any result derived from a Shield scan of these specific packages prior to this fix should be treated as untrustworthy until re-derived — not just incomplete.

**Fix approach:** When the requested version cannot be resolved in the registry, `Shield.score()` should return an explicit unresolved/no-data state rather than substituting a different version and returning a normal verdict. This mirrors the tri-state principle (exists / confirmed-absent / undetermined) already applied to the registry-existence check elsewhere in the system — the same discipline needs to apply here: a scanner that can't examine the thing it was asked to examine should say so, not quietly examine something else and report as if it succeeded.

**Downstream handling to decide:** once Shield returns an unresolved state instead of a score, decide how the Aggregator should treat it. Options include: treating unresolved-Shield the same as a missing pillar (fall back to the other two pillars' signals), or treating it as its own flag that forces a conservative outcome (e.g., WARN) since "the target version literally could not be examined" is itself a meaningful signal, especially for a version that's absent because it was security-purged. This decision should be made deliberately and documented, not left as an implicit side effect of whatever the Aggregator does by default with a null score.

**Validation:** re-run Shield against the same four spot-checked packages (and the remaining 11) and confirm the tarball actually scanned matches the requested version, or confirm an explicit unresolved state is returned when it doesn't. There should be no case where a requested version silently resolves to a different one without that being visible in the output.

---

## Step 3 — Re-run the full 179-record corpus and re-derive the 15-record outcome specifically

**Purpose:** Steps 1 and 2 together mean that, for the first time, the system will actually be attempting a genuine diff against genuine historical data for these 15 records, rather than either finding nothing (Step 1's bug) or silently scanning the wrong artifact (Step 2's bug). This is the run that answers a real, previously unanswered question: does manifest-first gating and cross-version AST diffing actually catch these real 2025/2026 compromises, or not?

**What to report, explicitly, for each of the 15:**
- Whether the historical predecessor now resolves correctly (should be yes, per Step 1's fix)
- Whether Shield's diff now runs against the genuine malicious tarball (should be yes, per Step 2's fix) — confirm this by checking that the scanned artifact's hash or version tag matches the requested malicious version, not a substituted one
- The actual capability diff Shield produces between the clean predecessor and the malicious version — new network calls, new `child_process` usage, new `process.env` access, or whatever the specific compromise introduced, cross-referenced against the incident writeups already gathered for these packages
- The final verdict (ALLOW/WARN/BLOCK) and which pillar drove it

**Important:** don't assume the fix means detection will now succeed. It's entirely possible some of these 15 will still be missed even with a genuine diff — if so, that's a legitimate, different finding (the diff logic itself failing to flag a real capability change it had full access to) and should be reported as such, not smoothed into an assumed success. Whatever the outcome, it's now a real number instead of an artifact of two bugs.

**Also re-run:** the full 179-record corpus end to end, not just the 15, since both fixes touch code paths (`get_previous_version`, `Shield.score()`) that other records may also pass through, even if less visibly affected. Confirm no other record's verdict changed as a side effect, and if any did, investigate before accepting the new run as final.

---

## Step 4 — Correct every downstream claim built on the old, incorrect explanation

**What needs correcting, specifically:**

1. **The original 17-record / 15-record finding.** The existing explanation ("0.0 recall due to npm having fully purged the compromised artifacts — a structural blind spot for content/tarball scanners") is now known to be false for these records. Replace it with whichever outcome Step 3 actually produces: either "the structural blind spot doesn't exist for these records; the true cause was two fixable bugs, now fixed, and detection now succeeds" or "the bugs were fixed, but the diff logic still misses these — here is what the genuine diff shows and why it wasn't flagged." Either is a legitimate, publishable finding. The currently-drafted explanation is not, since it's now contradicted by direct evidence.

2. **The threat-campaign walkthrough section** (already flagged as needing empirical rather than reasoned backing). The TanStack and axios entries in that section reasoned about what Shield "would" detect. Given that any actual scan of these packages prior to this fix was silently hitting the wrong artifact, those entries need to be rebuilt from the Step 3 re-run — a genuine scan against the genuine malicious version — rather than left as either reasoned claims or, worse, treated as already-empirically-confirmed based on a scan that wasn't real.

3. **The ablation table**, once the Investigation 1 fix (missing Stage-1 gate in `ablation.py`'s hand-duplicated aggregator logic) is mirrored in and re-run — this is a separate, already-diagnosed fix, low-risk, and should be applied alongside this work so the paper isn't juggling two different corrected-results passes.

4. **Anywhere else in the current paper draft** that references Shield's performance on these specific packages, or that cites the purge explanation as a general property of the system's design (rather than specific to these 15, which it no longer is) — search the draft for mentions of these package names and the "purge" framing, and verify each one against the new Step 3 results before leaving it in place.

**Validation:** every claim in the manuscript about these 15 records, and about Shield's cross-version diff capability generally, should be traceable to the post-fix Step 3 run — not to the pre-fix investigation, and not to reasoning about what the system "should" do.

---

## Sequencing

1. Step 1 and Step 2 can be implemented in parallel — they're independent bugs in different functions.
2. Step 3 depends on both being complete; don't partially re-run with only one fix in place, since Step 2 alone (without Step 1) would still find no predecessor to diff against, and Step 1 alone (without Step 2) would still risk scanning the wrong artifact if version resolution issues compound.
3. Mirror the Investigation-1 `ablation.py` gate fix in at the same time as Steps 1–2, so Step 3's full corpus re-run produces one clean, final set of numbers rather than requiring a second re-run later.
4. Step 4 is a documentation/manuscript pass and should only begin once Step 3's results are final and re-verified — don't draft the corrected narrative before the numbers it depends on are settled.