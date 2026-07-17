# CIDAS Further Improvement Plan — Validation Strengthening for IEEE Access

**Context for this plan:** the system-level engineering work is now in a genuinely strong place — the manifest-first gate, tri-state registry/version resolution, rate limiter, homoglyph normalization, and corrected corpus numbers all landed this cycle, and the ablation/ablation-sync bug is fixed. The assessment that the core contribution doesn't need redesigning is consistent with that work — this plan doesn't touch the architecture. It's entirely about validation depth, which is where a 179-package corpus and no external baseline comparison are the most likely things a reviewer pushes back on.

**How this plan differs from the reviewer's list:** the priorities below are the same items, reordered and scoped against what's actually achievable before a submission deadline, with an honest read on which items are cheap given work already done, which are expensive regardless, and which have a feasibility problem the original list doesn't flag (specifically: Snyk and Amalfi comparisons).

---

## Before anything else: recompute the numbers this plan will build on

Every item below — the baseline comparison, the corpus expansion, the threshold sensitivity sweep — needs the corrected post-fix numbers as its starting point, not the numbers from before the version-resolution and tri-state fixes. Confirm the manuscript sync pass (recall figures, ablation table, limitations section) is fully closed before starting new evaluation work, so the new work isn't built on top of numbers that are about to change again.

---

## Tier 1 — Do these three; they cover the most likely reviewer objections per unit of effort

### 1. Baseline comparison against tools that are actually comparable

**Reality check on scope, before committing to the full list:**
- **npm audit**: trivial to run, fully feasible, do this first.
- **OSV Scanner**: feasible, open-source, CLI-driven, comparable output format.
- **Socket.dev**: feasible if it has a free-tier CLI or API with reasonable rate limits; check this before committing, since usage limits could make a 179+-package sweep impractical on a free tier.
- **Amalfi**: the paper already cites Amalfi's own reported numbers (95 malicious packages found in 96,287 versions) rather than claiming a reproduction. Reproducing it requires access to its offline classifier pipeline and source-reproducibility infrastructure, which isn't public in a runnable form as far as this project's literature review found. Recommend keeping Amalfi as a cited-numbers comparison in the related-work table (already done) rather than attempting a live reproduction — flag this as a scoping decision in the paper rather than silently dropping it.
- **Snyk**: proprietary, commercial, and its detection logic isn't fully documented publicly. A live comparison is possible only through its commercial API/CLI, which may have cost or licensing constraints worth checking before committing engineering time to it. If infeasible, say so directly in the comparison section rather than omitting Snyk without explanation — a stated infeasibility reads far better to a reviewer than a silent gap.

**Implementation plan:**
1. Run npm audit, OSV Scanner, and (if feasible) Socket.dev against the exact same 179-record corpus already used for CIDAS's own evaluation — same package/version pairs, so the comparison is apples-to-apples rather than approximate.
2. For each tool, record: verdict per record (however each tool expresses it — advisory-only tools like npm audit may not have an ALLOW/WARN/BLOCK equivalent, so map their output to the closest comparable category and state the mapping explicitly), latency per scan, and whether the tool operates pre-install or post-install (this distinction is central to CIDAS's own positioning and should be reported as a dimension of comparison, not just accuracy).
3. Build a single results table: precision, recall, F1, FPR, median latency, and execution stage (pre-install/post-install/CI-only) per tool, CIDAS included.
4. Write the comparison honestly — if CIDAS underperforms a specific tool on a specific threat category (e.g., npm audit likely has near-perfect recall on packages with an existing CVE, since that's exactly what it's built for), report that directly rather than only showcasing categories where CIDAS wins. A comparison that only shows favorable results reads as cherry-picked; one that shows CIDAS's actual differentiator (pre-install interception, context-fit, hallucination guard — none of which the other tools do at all) alongside honest gaps in raw detection rate on categories those tools specialize in is a stronger, more credible paper.

**Validation:** the comparison table should be reproducible by a third party re-running the same corpus against the same tool versions — pin tool versions explicitly in the methodology.

---

### 2. Corpus expansion, scoped realistically

**Reality check on the 1,000–5,000 target:** this is achievable primarily on the benign side (top-N npm packages by download count is a simple, defensible sampling strategy) and much harder on the malicious/typosquat/hallucinated side, since those categories require either verified historical incidents (a finite, slow-growing list) or synthetically constructed cases (which the paper should be careful not to over-rely on, since synthetic typosquats and synthetic hallucinations are weaker evidence than verified real-world incidents — this is already flagged correctly as a threats-to-validity item).

**Implementation plan:**
1. **Benign corpus**: expand from top-500 to a larger sample (e.g., top-2,000 or top-5,000 by download count), explicitly stratified to include a range outside the most popular tier — very popular packages are the easiest case for a reputation-based system; the interesting false-positive risk is in the long tail of legitimate-but-less-popular packages, which the current top-500 corpus likely underrepresents. This directly strengthens the false-positive characterization the reviewer feedback specifically asks for.
2. **Typosquat corpus**: expand the synthetic generation methodology's coverage (more target packages, more mutation strategies — affix variants, edit-distance variants, and now homoglyph variants given the normalization work just landed) rather than just scaling up volume on the existing generation strategy. Document the generation methodology precisely enough that a reviewer can assess whether it's representative of real attacker behavior.
3. **Malicious/hallucinated corpus**: grow this more slowly and deliberately — every addition should be a verified real incident (per the standard already applied to the 17 additions this session, with primary-source verification for each), not a volume target hit with lower-confidence entries. It's better to report a smaller, fully verified malicious corpus than a larger one with unverified entries, given this paper's now-established pattern of catching and correcting exactly that kind of provenance problem.
4. Report corpus size growth transparently in the methodology section as an evolving corpus, with a version/date stamp, so future revisions can cite which corpus version produced which numbers — this also directly supports the artifact-availability item below.

**Validation:** re-run the full evaluation and ablation pipeline against the expanded corpus, and confirm the precision/recall/FPR figures are reported with the corpus composition explicitly stated (already partially done via the benign-corpus-composition caveat added this session — extend that same discipline to the expanded corpus).

---

### 3. Threshold sensitivity analysis

**Why this is high-value relative to its cost:** every threshold currently in the system (embedding similarity cutoff, download-disparity 5%, package-age cutoffs, WARN/BLOCK score cutoffs, pillar weights) is already a configurable parameter, not something requiring architectural change to vary — this is a sweep over existing configuration, not new system development, which makes it one of the cheapest high-value additions on this list.

**Implementation plan:**
1. Identify the small set of parameters most likely to draw reviewer scrutiny: the 5% download-disparity threshold and 30-day/1-year age thresholds in Sentinel's reputation corroboration, the WARN(40)/BLOCK(80) score cutoffs in the Aggregator, and the three pillar weights (already partially covered by the existing eight-configuration ablation, but that ablation tests binary on/off per pillar, not a continuous sweep of relative weight).
2. For each parameter, run the evaluation corpus across a reasonable range of values (e.g., download-disparity at 1%, 5%, 10%, 20%) and plot precision/recall/F1/FPR as a function of the parameter, rather than just reporting the single chosen value's performance.
3. Use this to justify the chosen defaults explicitly in the paper — "5% was chosen because recall drops sharply below X% while FPR increases sharply above Y%" is a far stronger methodological statement than stating the threshold without justification, which is the current state.
4. Where a parameter shows a flat or insensitive response across a wide range, report that too — it's a legitimate finding (the system is robust to that parameter's exact value) and costs nothing extra to include once the sweep is done.

**Validation:** each swept parameter should produce a small table or plot showing the metric response curve, with the chosen production value marked and justified against that curve.

---

## Tier 2 — Do these if time allows after Tier 1; each is lower cost than it looks given existing instrumentation

### 4. Performance overhead (CPU, memory, idle, throughput)

**Why this is cheaper than it appears:** the daemon already produces latency profiling (cache-hit/cache-miss/cold-concurrent tables exist in the current draft). Extending this to CPU and memory is largely a measurement-harness addition around code that already runs the same operations, not new functionality.

**Implementation plan:**
1. Measure daemon idle memory/CPU footprint (steady-state, no active scans) — this addresses the "will this slow down my machine just by running" question directly.
2. Measure per-scan CPU/memory delta across the same cache-hit/cache-miss/cold-concurrent conditions already used for latency, so the performance story is told consistently across all four dimensions (latency, CPU, memory, throughput) rather than latency alone.
3. Measure extension-side overhead separately from daemon-side, since these are different processes with different resource profiles and a reviewer may reasonably ask about either in isolation.
4. Report scan throughput (packages/second under sustained load) as a distinct number from single-scan latency, since a developer with a large dependency tree cares about aggregate throughput, not just individual scan speed.

**Validation:** report all four dimensions in a single consolidated performance table alongside the existing latency table, so a reviewer sees the full resource picture in one place.

### 5. False-positive analysis (qualitative, not just the FPR number)

**Implementation plan:**
1. Pull every false-positive record from the current benign-corpus evaluation (the corrected run should now be at FPR 0.0 on the current corpus, so this becomes more relevant once the expanded corpus from item 2 surfaces new false positives, which it likely will at a larger scale).
2. For each, categorize why it occurred (naming collision, low download count for a legitimately new-but-benign package, context mismatch for a package genuinely used outside its "expected" project type, etc.) and connect each category back to a specific system mechanism (Sentinel's disparity threshold, Contextify's embedding fit, etc.).
3. Where possible, show a concrete before/after: a false positive that the tri-state or rate-limiter fixes already this session resolved is good supporting evidence that the system actively handles its own failure modes rather than just reporting a low aggregate number.

### 6. Statistical confidence (bootstrap / confidence intervals)

**Implementation plan:** bootstrap resampling over the evaluation corpus is a standard, low-engineering-cost addition once the corpus and evaluation pipeline are stable — resample the corpus with replacement across many iterations, recompute precision/recall/F1 each time, and report confidence intervals around the point estimates already in the results table. This is most valuable to add *after* the corpus expansion (item 2), since confidence intervals on a 179-record corpus will be wide enough to somewhat undercut the paper's own precision claims — better to compute this once on the larger, expanded corpus than twice.

### 7. Scalability evaluation (large dependency trees, concurrent scans, cache under load)

**Implementation plan:**
1. Construct or select a small number of real projects with large dependency trees (hundreds to low thousands of transitive dependencies) and run a full-tree scan, reporting total wall-clock time and cache hit rate.
2. Specifically stress-test the rate limiter and download-count cache added this session under this kind of load — this is a natural extension of the work already done to fix the rate-limiting false negative, and demonstrates the fix holds up under the exact kind of load (many packages, many first-time lookups) that originally broke it.
3. Report concurrent-scan behavior (multiple projects/developers hitting the daemon simultaneously) if the daemon is architected to support this — if it isn't, state that as a current scope boundary rather than testing something the system isn't designed for.

---

## Tier 3 — Nice to have; sequence after submission-critical work unless time is genuinely abundant

### 8. Real-world case studies (React, Next.js, Express-style projects)

Lower cost than a user study, and produces concrete, narratable results ("scanning a fresh Next.js project's dependency tree, CIDAS flagged X, correctly allowed Y, and would have caught Z had it been present at the time of an actual historical incident"). Worth doing if item 7's dependency-tree testing is already being set up, since the infrastructure overlaps substantially.

### 9. User study / developer usability

Genuinely valuable but the highest-cost item on this list relative to submission timelines — recruiting even 10–20 developers, running a structured evaluation, and analyzing the results properly is a multi-week undertaking on its own. Recommend treating this as a follow-up paper or a "future work" item explicitly named in the conclusion, rather than attempting a rushed version that produces weak evidence. A poorly-powered usability study is worse for the paper than no usability study plus an honest statement that it's planned future work.

### 10. Artifact availability (repo, reproducibility package, evaluation/corpus scripts)

This should not be deprioritized on difficulty grounds — it's mostly packaging work, not new research, and IEEE Access reviewers increasingly expect it. Recommend doing this in parallel with Tier 1, not after, since a clean reproducibility package is also what makes items 1–3 checkable by reviewers in the first place. Include: the evaluation corpus with provenance/verification notes per entry, the evaluation and ablation scripts, and instructions to reproduce the baseline-comparison table.

### 11. Expanded threats to validity

Once items 1–7 are done, several of them will surface their own threats-to-validity points naturally (synthetic typosquat generation methodology from item 2, corpus construction bias from item 2, npm-only applicability, registry-metadata dependence already partially covered by this session's tri-state work). Write this section last, after the other work is done, so it reflects the actual limitations surfaced by the expanded validation rather than being drafted speculatively in advance.

---

## What not to touch

Consistent with the assessment that the core contribution doesn't need redesigning: the four-pillar architecture, the threat model, and the ablation study's structure should stay as-is. The one caveat is that the ablation study's *numbers* need to reflect the already-completed corrected run (post version-resolution and tri-state fixes) before any of the above validation work builds on top of it — this isn't a design change, just confirming the foundation this plan builds on is already the corrected one.

---

## Suggested sequencing given limited pre-submission time

1. **Confirm the manuscript sync pass is fully closed** (prerequisite, not optional).
2. **Tier 1, items 1–3, in parallel** where possible — the baseline comparison (item 1) and corpus expansion (item 2) can run concurrently since they use overlapping but not identical infrastructure; threshold sensitivity (item 3) is independent of both and can run alongside.
3. **Artifact packaging (item 10)** in parallel with Tier 1, since it's mostly packaging existing work plus whatever Tier 1 produces.
4. **Tier 2 items, in order of cost**: performance overhead (item 4) and false-positive analysis (item 5) are both cheap given existing instrumentation; statistical confidence (item 6) should follow the corpus expansion so it's computed once on final data; scalability (item 7) can run whenever the rate-limiter/cache infrastructure is convenient to stress-test.
5. **Tier 3 items** only if time remains — explicitly plan to name items 8–9 as future work in the conclusion if they don't fit, rather than cutting them silently.
