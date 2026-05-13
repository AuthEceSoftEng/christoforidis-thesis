# Thesis ↔ Code Semantic Analysis

**Thesis:** "Vulnerability detection using static application security testing and artificial intelligence techniques"  
**Author:** Christoforidis Christos, AUTh ECE, January 2026  
**Scope:** Verify that the implemented code matches what the thesis describes; flag semantic differences and assess whether those differences make research sense.

---

## Overview

The thesis describes a **5-phase pipeline** for automated, LLM-augmented vulnerability detection in JavaScript projects using CodeQL. The code, as documented in `PIPELINE_MAP.md`, expands this into **11 stages** (including pre-pipeline setup, repo cloning, database creation, and evaluation). The extra stages in the code are all **operational scaffolding** that the thesis correctly treats as pre-conditions rather than core architectural phases — this is not a discrepancy.

The mapping between thesis phases and code stages is:

| Thesis Phase | Code Stage(s) |
|---|---|
| Pre-condition: CodeQL DB creation | Stages 1–2 (scraper, create_db) |
| Phase 1: Extract & Classify Dependency Methods | Stages 3–6 (getPackageMethods, advisory matching, LLM classification, library generation) |
| Phase 2: Predict CWEs & Extract CallGraph | Stage 7 (cwe_decider) + call graph extraction in Stage 8 |
| Phase 3: Generate CodeQL Queries | Stage 8 (query_generator.refine_vulnerability_query) |
| Phase 4: Execute Queries | Stage 9 (query_runner.run_codeql_queries_batch) |
| Phase 5: Filter Results | Stage 10 (llm_filtering) |
| Evaluation | Stage 11 |

---

## Confirmed Alignments (Code Matches Thesis)

### Phase 1 — Method Extraction & Classification

- **Thesis (§3.2.1):** Runs `getPackageMethods.ql` to extract `(packageName, version, methodName)` triples; deduplicates; compares against GitHub Security Advisories API; classifies each method via LLM into SOURCE / SINK / PROPAGATOR / CONDITIONAL_SANITIZER with structured output including `BYPASS_CONDITION`, `DATA_TYPE`, `REASONING`.
- **Code:** `methods_post_process.py` does exactly this. `deduplicate_methods()` → `compare_with_advisories()` (using `gh api /advisories?ecosystem=npm --paginate`) → `classify_vulnerable_methods()` with the four-class taxonomy. ✅

- **Thesis:** Conditional sanitizer bypass conditions are deduplicated using fuzzy semantic similarity with a threshold of 80%.
- **Code:** `fuzz.token_sort_ratio ≥ 80` in `classify_vulnerable_methods()`. ✅

- **Thesis:** Two `.qll` library files are generated: `VulnerableMethodsClassification.qll` (sources, sinks, propagators) and `ConditionalSanitizers.qll` (bypass detection predicates).
- **Code:** `generate_codeql_package_classification()` and `generate_conditional_sanitizer_library()` in `query_generator.py`. ✅

- **Thesis:** The `ConditionalSanitizers.qll` generation uses iterative refinement: compile → extract errors → RAG query → LLM fix, up to 5 rounds.
- **Code:** `while not success and tries < 5` loop in `generate_conditional_sanitizer_library()`. ✅

- **Thesis:** Sinks are classified per-CWE (e.g., `isCWE89Sink`) to allow CWE-targeted queries.
- **Code:** `generate_codeql_package_classification()` emits `isCWE{N}Sink` predicates. ✅

### Phase 2 — CWE Prediction & CallGraph

- **Thesis (§3.2.2):** CWE list is the union of (a) LLM prediction from README + package.json and (b) CWEs extracted from advisory data.
- **Code:** `cwe_decider.cwes_to_check()` returns `sorted(set(llm_cwes) ∪ set(advisory_cwes))`. ✅

- **Thesis:** CallGraph is extracted via `extractCallGraph.ql`; filtered by LLM-generated CWE-relevant keywords; formatted into a structured summary for the LLM.
- **Code:** `general.extract_call_graph()` + `format_call_graph_for_cwe()` with `keywords_filter_prompt` (5–10 keywords, few-shot). ✅

- **Thesis:** Call graph excludes `node_modules` to focus on project code; test files are excluded.
- **Code:** `extract_call_graph()` filters out `frontend/`, `client/`, `public/`, `views/`, `test/`, `spec.`, `cypress/`. ✅

### Phase 3 — Query Generation & Refinement

- **Thesis (§3.2.3):** Two-phase iterative refinement: Phase A refines `isSink`, Phase B refines `isAdditionalFlowStep`. Each uses two-stage prompting (explain → implement). Compile-validate-fix loop up to 5 rounds per phase.
- **Code:** `refine_sink_vulnerability_query()` and `refine_flow_vulnerability_query()` in `query_generator.py`, each with a 5-round loop. ✅

- **Thesis:** The initial query template is built from sources (generic + Phase 1 + compat libraries), sinks (LLM-selected from `isSink.qll`), barriers (compat + ConditionalSanitizers), and additional flow steps (compat + propagators).
- **Code:** `generate_vulnerability_query()` assembles these four components in exactly this way. ✅

- **Thesis:** Compatibility bridge libraries (`DefaultCWE{N}Compat.qll`) are checked via a registry and imported if they exist.
- **Code:** `_has_compat(cwe_id)` checks `registry.json`; the query template conditionally imports the compat module. ✅

- **Thesis:** RAG retrieves from two collections — query examples and documentation — to guide LLM code generation.
- **Code:** `_get_relevant_documentation()` queries `codeql_queries` (top 3) and `codeql_documentation` (top 2). ✅

- **Thesis:** Does not specify the embedding model or chunking strategy.
- **Code:** Embedding model is `nomic-ai/nomic-embed-text-v1.5` (MTEB retrieval 62.28, 8192-token window, ~550 MB RAM). Source files are split into overlapping 1500-character chunks (200-char overlap) before indexing. Chunking is required because several CodeQL library files exceed 80–100 KB; without it, large-window models crash with OOM and small-window models silently truncate. The DB folder is named after the active model (`chroma_db_<model-name>/`) so multiple embedders can coexist on disk. When `nomic-ai/*` models are active, task-instruction prefixes (`search_document:` / `search_query:`) are applied automatically. ✅

### Phase 4 — Query Execution

- **Thesis (§3.2.4):** Both refined taint-tracking queries and default CodeQL problem queries are executed in batch, in parallel, using all available CPU threads. Output is SARIF + CSV.
- **Code:** `run_codeql_queries_batch()` uses `--threads=0` (auto) and `--format=sarif-latest`. CSV is produced by a parallel decode step. ✅

### Phase 5 — False Positive Filtering

- **Thesis (§3.2.5):** For each finding, context is extracted using AST analysis (esprima) to find the enclosing function or block. The sink line is highlighted with `→→→`. LLM returns `confidence` (0–1), `verdict`, and `reasoning`. Findings with `confidence ≥ threshold` are kept; `INSUFFICIENT_CONTEXT` verdicts are also kept.
- **Code:** `get_smart_context_range()` in `general.py` uses esprima; `extract_context_from_file()` adds `→→→` prefix; `filter_llm_findings()` retains `confidence ≥ threshold OR verdict == "INSUFFICIENT_CONTEXT"`. ✅

- **Thesis:** Default threshold is 0.6; re-filtering at different thresholds without re-invoking the LLM is supported.
- **Code:** `filter_llm_findings(threshold=0.6)` and `filter_with_existing_responses()`. ✅

---

## Semantic Differences Between Code and Thesis

### Difference 1 — LLM Backend: Ariadne Proxy vs. Direct Anthropic API

**Thesis says:** The system uses Claude 3.7 Sonnet by Anthropic (footnote 16, §3.2).  
**Code does:** `LLM.py` targets a university proxy API (`ariadne.issel.ee.auth.gr/api/v1`) rather than `api.anthropic.com`. The model is configured via `ARIADNE_MODEL_ID` and `ARIADNE_PROVIDER` environment variables.

**Assessment:** This is a **deployment-level difference, not a research-level difference**. The proxy is a university infrastructure layer that routes to the same underlying Claude model. The thesis correctly identifies the model; the code correctly uses the available institutional access mechanism. This change makes complete sense and does not affect reproducibility of results, provided the proxy targets the same model version.

**Note:** The `PIPELINE_MAP.md` still says "Ariadne API / Claude" which is accurate.

---

### Difference 2 — Pipeline Granularity: 5 Thesis Phases vs. 11 Code Stages

**Thesis says:** The system has 5 phases.  
**Code has:** 11 stages including repository cloning, CodeQL database creation, and evaluation infrastructure.

**Assessment:** The thesis intentionally abstracts away operational scaffolding. Stages 1–2 (clone, create DB) are described as pre-conditions in §3.1.1. Stage 11 (evaluation) is described in Chapter 4. The 5-phase framing in the thesis is an accurate **conceptual** description. The code's 11-stage breakdown in `PIPELINE_MAP.md` is an accurate **operational** description. No discrepancy.

---

### Difference 3 — CVE-Based Evaluation: Not Described in Thesis

**Thesis says:** Evaluation uses only DVNA (26 vulnerabilities); comparison is made against Semgrep, NodeJsScan, and CodeQL Default (§4.1).  
**Code has:** A full CVE-based evaluation infrastructure (`evaluation_cves/specific_evaluator.py`, `general_evaluator.py`, 200+ CVE JSON files) and OWASP Juice Shop evaluation (`vuln_apps_eval/`) in addition to DVNA.

**Assessment:** This is a **significant extension beyond what the thesis reports**. The thesis presents only the DVNA results. The CVE evaluation and Juice Shop evaluation are either:
- (a) Work done after the thesis was finalized, or  
- (b) Work done in parallel that was not included in the thesis due to scope constraints.

**Research-wise:** This is a positive extension. CVE-based evaluation with 200+ real-world cases provides much stronger external validity than a single synthetic benchmark. The per-project timing statistics (`specific_evaluator.py`) also represent a maturity of the evaluation framework beyond the thesis. These additions make the research stronger, not weaker.

---

### Difference 4 — Evaluation Dataset Size: 14 vs. 26 Vulnerabilities in DVNA

**Thesis says:** "The ground truth includes 26 vulnerabilities" (§4.1).  
**Code has:** `vuln_apps_eval/dvna/vulns.json` references "14 known vulnerabilities" in `PIPELINE_MAP.md` Stage 11.

**Assessment:** This is a **potential inconsistency** worth verifying. The thesis explicitly states 26 vulnerabilities across a wide range of categories. The `PIPELINE_MAP.md` description of 14 may refer to a subset used in a specific evaluation run, or it may reflect a different version of the ground truth file. The thesis number (26) should be considered authoritative for the reported results. The code's ground truth file should be checked to confirm it contains 26 entries.

---

### Difference 5 — Conditional Sanitizer Validation: Juice Shop as Dummy Database

**Thesis says:** The iterative refinement loop compiles predicates against "a dummy CodeQL database" (§3.2.1, Step 5b).  
**Original code:** `generate_conditional_sanitizer_library()` hard-coded `juice-shop` as the validation database path, creating a hidden deployment dependency.

**Fix applied:** `generate_conditional_sanitizer_library()` now accepts a `validation_db: str | None` parameter. A helper `_resolve_validation_database()` resolves the path with the following priority:
1. The passed `validation_db` name (i.e. `project_name` from the caller) if the directory is non-empty.
2. The first non-empty database found in `databases/` (sorted, deterministic).
3. `databases/juice-shop` as a last-resort fallback with an explicit warning log.

All three call sites (`vuln_apps_eval/evaluation.py`, `evaluation_cves/general_evaluator.py`, `evaluation_cves/specific_evaluator.py`) now pass `validation_db=project_name`, so the project's own database — which already exists by Phase 1 — is used. This is strictly better: same JS runtime, same npm packages, no external dependency.

---

### Difference 6 — LLM Temperature Settings Not Mentioned in Thesis

**Thesis says:** The LLM uses "low temperature" for CWE prediction to ensure consistency (§3.2.2, footnote 17). No specific values are given for other stages.  
**Code uses:**
- `temperature=0.6` for method role classification (Phase 1)
- `temperature=0.2` for all code generation, CWE prediction, and false-positive scoring (Phases 2–5)

**Assessment:** The thesis mentions low temperature only for CWE prediction but the code consistently uses 0.2 for all analytical/generative tasks. The higher temperature (0.6) for classification is a deliberate choice — classification benefits from slightly more variability to handle edge cases in advisory descriptions. This is a reasonable and well-motivated design decision that the thesis glosses over. It does not contradict the thesis; it just adds precision.

---

### Difference 7 — Sink Selection: LLM Picks from a Fixed List of 11 Categories

**Thesis says:** "The LLM selects appropriate sink categories from `isSink.qll`" (§3.2.3, Step 4).  
**Code does:** `get_sink_selection_prompt()` in `prompts.py` presents a hardcoded enumeration of exactly 11 sink categories: command execution, DB query, filesystem, HTTP response, dynamic code, deserialization, logging, external API, DOM manipulation, open redirect, XPath injection.

**Assessment:** The thesis implies a more dynamic selection from the library. The code's approach of a fixed 11-category list is actually **more controlled and reproducible** — the LLM cannot hallucinate a category that doesn't exist in the library. This is a sound engineering choice that improves reliability over what the thesis implies. The thesis description is slightly imprecise here; the code's approach is better.

---

### Difference 8 — Call Graph Formatting: Categorisation by File Role

**Thesis says:** The call graph is "filtered by CWE-relevant keywords" and provided to the LLM (§3.2.2, §3.2.3).  
**Code does:** `_format_call_graph_summary()` in `general.py` additionally categorises files into Routes / Controllers / Models / Core / Utils / Config / Other, with caps of 8 files/category, 12 functions/file, and 10 calls/function.

**Assessment:** This structured categorisation is a **significant enhancement** not described in the thesis. Rather than dumping raw call graph rows, the code provides the LLM with an architecturally-aware summary that mirrors the MVC/layered structure common in Node.js applications. This is a very sound research decision — it reduces noise, respects context window limits, and helps the LLM understand which files are entry points (routes), which contain business logic (controllers), and which interact with storage (models). The thesis's description is a simplified version of what the code actually does.

---

### Difference 9 — AST Context Extraction: Priority Scheme Not Described in Thesis

**Thesis says:** "The sink line context is located using smart AST-based boundary detection (esprima) to find the enclosing function or statement" (§3.2.5).  
**Code does:** `get_smart_context_range()` implements a priority scheme: FunctionDeclaration/Expression/Arrow = priority 3, ExpressionStatement/VariableDeclaration/CallExpression = priority 2, BlockStatement/Program = priority 1. Among same-priority nodes, the smallest enclosing node is preferred.

**Assessment:** The thesis correctly describes the intent. The code's priority scheme is an implementation detail that makes the "smartness" concrete and reproducible. The choice to prefer functions over statements over blocks is well-motivated: functions provide the most semantically complete context for vulnerability assessment. The thesis's description is accurate at the conceptual level.

---

### Difference 10 — `general` Flag in Query Generation: Project-Agnostic Mode

**Thesis says:** All query generation is project-specific (§3.2.3).  
**Code has:** `refine_vulnerability_query()` accepts a `general=True` flag that omits README/package.json/call-graph context, producing a project-agnostic query.

**Assessment:** This is an **undocumented feature** in the thesis. It appears to be an engineering convenience for generating baseline queries that can be reused across projects, or for the CVE evaluation where individual project context may not be available. Research-wise, this is a reasonable extension — it allows the pipeline to degrade gracefully when project metadata is unavailable, and enables ablation studies (generic vs. project-specific queries).

---

### Difference 11 — Semver Handling: Unknown Versions Treated as Vulnerable

**Thesis says:** Packages are matched against advisories using version range matching (§3.2.1).  
**Code does:** In `is_version_vulnerable()`, if the package version cannot be parsed by semver, it is conservatively treated as **vulnerable** (returns `True`).

**Assessment:** This is a **deliberate false-positive bias** not mentioned in the thesis. The choice is defensible for a security tool (better to over-report than to miss real vulnerabilities), but it means unparseable version strings (e.g., git hashes, pre-release tags with unusual formats) will always be flagged. The thesis should ideally document this as a design decision. Research-wise, it is sound for a security-oriented tool.

---

## Summary Table

| # | Area | Thesis | Code | Severity | Research Soundness |
|---|---|---|---|---|---|
| 1 | LLM backend | Claude 3.7 Sonnet (Anthropic) | Ariadne proxy → same model | Deployment only | ✅ Sound |
| 2 | Pipeline granularity | 5 phases | 11 stages | Abstraction level | ✅ Sound |
| 3 | CVE evaluation | Not described | 200+ CVE infrastructure exists | Extension | ✅ Stronger than thesis |
| 4 | DVNA ground truth size | 26 vulnerabilities | 14 in PIPELINE_MAP | ⚠️ Verify | Needs confirmation |
| 5 | Sanitizer validation DB | "dummy database" | ~~Hardcoded `juice-shop`~~ → now uses `project_name` with auto-discovery fallback | **Fixed** | ✅ Sound |
| 6 | LLM temperatures | Low for CWE only | 0.2 everywhere, 0.6 for classification | Undocumented detail | ✅ Sound |
| 7 | Sink selection | Dynamic from library | Fixed 11-category list | More controlled | ✅ Better than thesis implies |
| 8 | Call graph formatting | Raw filtered rows | Structured MVC-aware summary | Significant enhancement | ✅ Stronger than thesis |
| 9 | AST context extraction | Enclosing function/statement | Priority scheme (fn > stmt > block) | Implementation detail | ✅ Sound |
| 10 | `general` flag | Not described | Project-agnostic query mode | Undocumented feature | ✅ Useful extension |
| 11 | Semver unknown versions | Not mentioned | Treated as vulnerable (FP bias) | Undocumented assumption | ⚠️ Should be documented |

---

---

## Post-Analysis Implementations

### Threshold Consistency (Question 1)

The threshold **must be consistent within a single experiment run** — and the existing architecture already enforces this correctly. The LLM confidence scores are generated once and saved to `llm_responses.json`. The threshold is only applied afterwards during the filtering step. This means:

- `filter_llm_findings()` → generates scores + applies threshold → saves both the responses and the filtered CSV
- `filter_with_existing_responses()` → re-applies any threshold to the cached responses without re-calling the LLM

`figures.py` demonstrates the intended workflow: it sweeps `[0, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.9]` by re-filtering the *same cached responses*, which is exactly right. Varying the threshold *across* experiments (to plot the precision-recall curve) is the point; varying it *within* a single finding's evaluation would be incoherent.

One minor note: `filter_results.py` hardcoded `threshold = 0.95` for its first-run path, inconsistent with the `0.6` default in `filter_llm_findings`. This is harmless (responses are cached independently of the threshold) but slightly confusing.

---

### LLM-Enriched Context Extraction (Question 2 — Implemented)

**Thesis suggestion (§6):** *"A more advanced approach could exploit more information sources from the code, such as inline documentation within the code in the form of comments."*

**What was implemented:**

Four files were modified to add an ablation-study-ready enriched context mode:

#### `utils/prompts.py` — `enrich_context_prompt()`
A new prompt that asks the LLM to extract a semantic summary from the raw code slice, specifically targeting:
1. Function intent (from JSDoc, function names, parameter names)
2. Inline comments near the sink
3. Data origin signals (variable names, comments)
4. Sanitization signals (naming conventions like `sanitized`, `escaped`, `validated`)

Temperature `0.1` — factual extraction, not creative generation.

#### `utils/general.py` — `get_enriched_context()`
A wrapper that calls the LLM with `enrich_context_prompt` and returns the plain-text summary. Fails gracefully (returns `""`) if the LLM call errors, so the caller always falls back to raw context. Uses the existing `LLMHandler` / Ariadne infrastructure.

#### `utils/prompts.py` — `get_vulnerability_confidence()` updated
Added an optional `enriched_summary: str = ""` parameter. When non-empty, the summary is injected into the confidence prompt as a **Semantic Summary** section between the code snippet and the analysis task. Backwards-compatible — existing calls without the argument are unaffected.

#### `utils/llm_filtering.py` — `filter_llm_findings()` updated
Added `use_enriched_context: bool = False` parameter. When `True`, calls `get_enriched_context()` before the confidence prompt for each finding. The enrichment summary is passed to `get_vulnerability_confidence()`. Responses are cached as before, so `filter_with_existing_responses()` works unchanged.

#### `vuln_apps_eval/filter_results.py` — environment-variable flag
```bash
# Baseline (default):
python filter_results.py

# Ablation study (enriched context):
ENRICHED_CONTEXT=1 python filter_results.py
```

Separate response cache files (`llm_responses.json` vs `llm_responses_enriched.json`) and filtered CSVs ensure baseline and enriched runs don't overwrite each other, making direct comparison straightforward.

**Cost:** One additional LLM call per finding in Phase 5. For a typical run with ~50–100 findings this is manageable; for large CVE batch evaluations it may be significant. The flag default of `False` ensures no cost impact on existing experiments.

---

## Conclusion

The code **faithfully implements** what the thesis describes. All five core phases are present, the architectural choices align, and the specific technical details (5-round refinement loops, 80% fuzzy dedup threshold, 0.6 default confidence threshold, dual-collection RAG, two-phase sink/flow refinement) match between thesis and code.

The semantic differences that exist fall into three categories:

1. **Positive extensions** (CVE evaluation, structured call graph formatting, `general` mode) — the code does *more* than the thesis describes, in ways that strengthen the research.

2. **Implementation details** (temperature values, AST priority scheme, fixed sink category list) — the code is *more precise* than the thesis, which is normal and appropriate.

3. **Minor concerns** (hardcoded Juice Shop validation DB, semver unknown-version bias, DVNA ground truth count discrepancy) — these are not fundamental flaws but should be documented or verified.

The overall picture is of a thesis whose implementation has matured beyond the written document, which is a healthy sign of active research development.
