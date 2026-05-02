# Pipeline Map — LLM-Augmented Static Analysis for JavaScript Vulnerability Detection

This document maps each stage of the vulnerability detection pipeline to the files that implement it, describing what happens at each step.

---

## Pre-Pipeline: One-Time Setup

### Vector Database Construction
**Files:** `vector_db/extraction.py`, `vector_db/create_vector_db.py`  
**Output:** `vector_db/chroma_db/`

Run once before the main pipeline. Raw CodeQL documentation (`.md`, `.ql`, `.qll`, `.rst`) placed in `vector_db/docs_original/` is first converted to plain text files in `vector_db/docs_txt/` by `extraction.py`. Then `create_vector_db.py` reads those text files and builds a **ChromaDB** persistent vector database with two separate collections:
- `codeql_queries` — indexed `.ql` / `.qll` examples
- `codeql_documentation` — indexed `.rst` / `.md` reference docs

Embeddings are produced by the `all-MiniLM-L6-v2` SentenceTransformer model. This database is later queried (RAG) during query refinement to give the LLM relevant CodeQL context.

---

## Main Pipeline (per target project)

The pipeline is orchestrated by the evaluator scripts:
- **CVE evaluation (with timing stats):** `evaluation_cves/specific_evaluator.py`
- **CVE evaluation (simpler):** `evaluation_cves/general_evaluator.py`
- **Vulnerable app evaluation:** `vuln_apps_eval/evaluation.py`

---

### Stage 1 — Clone Repository at Vulnerable Commit
**File:** `utils/scraper.py` → `clone_vulnerable_repos()`  
**Input:** CVE JSON files in `evaluation_cves/all/` or `evaluation_cves/mini_evaluation/`  
**Output:** Cloned repo in `codebases/<project-name>-<short-commit>/`

Reads each CVE JSON file to extract the repository URL and the **pre-patch commit hash** (`prePatch.commit`). Clones the repository with `git clone` and checks out that exact commit, giving a snapshot of the codebase as it existed when the vulnerability was present. Already-cloned repos are skipped.

> For vulnerable-app evaluation (DVNA, Juice Shop), source code is placed manually in `codebases/<app-name>/`.

---

### Stage 2 — Create CodeQL Database
**File:** `utils/create_db.py` → `create_codeql_database()`  
**Input:** Source directory in `codebases/`  
**Output:** CodeQL database in `databases/<project-name>/`

Runs `codeql database create` against the JavaScript source tree. The database is the compiled, queryable representation of the code that all subsequent CodeQL queries run against. If a database already exists the user is prompted to overwrite or reuse it.

---

### Stage 3 — Extract npm Dependency Method Calls
**Files:** `codeql/getPackageMethods.ql`, `utils/query_runner.py` → `run_codeql_query_tables()`, `utils/methods_post_process.py` → `deduplicate_methods()` + `methods_to_json()`  
**Output:** `output/<project>/methods.csv`, `methods_processed.csv`, `methods.json`

Runs the CodeQL query `getPackageMethods.ql` against the database. This query statically identifies every call to a method from an npm package (i.e. `require('pkg').method()`), recording the package name, version, and method name. Results are decoded from BQRS to CSV, deduplicated on `(packageName, version, methodName)`, then serialised to JSON for the next stage.

---

### Stage 4 — Match Dependencies Against GitHub Security Advisories
**File:** `utils/methods_post_process.py` → `compare_with_advisories()` + `get_npm_advisories()` + `is_version_vulnerable()`  
**Output:** `output/<project>/methods_vulnerable.json`

Fetches the full list of npm advisories from the **GitHub Security Advisories API** (`gh api /advisories?ecosystem=npm --paginate`). Each extracted package+version is compared against every advisory using semantic version range matching (`semver`). Packages whose version falls within a vulnerable range (and before the first patched version) are flagged. The output JSON records the matched advisory summary, severity, CWE IDs, and the list of vulnerable functions named in the advisory.

---

### Stage 5 — LLM Classification of Vulnerable Methods
**File:** `utils/methods_post_process.py` → `classify_vulnerable_methods()`  
**Prompt template:** `utils/prompts.py` → `get_classifying_methods_prompt()`  
**LLM handler:** `utils/LLM.py` → `LLMHandler`  
**Output:** `output/<project>/methods_vulnerable_classified.json`

For every method of every vulnerable package, a prompt is sent to **Claude** (via the Ariadne API) asking it to classify the method into one of four taint-analysis roles:

| Classification | Meaning |
|---|---|
| `SOURCE` | Introduces untrusted data into the program |
| `SINK` | Dangerous operation that should not receive untrusted data |
| `PROPAGATOR` | Passes taint from input to output |
| `CONDITIONAL_SANITIZER` | Sanitizes data only under certain conditions (can be bypassed) |

The LLM also returns a `bypass_condition` (for sanitizers), a `data_type`, and a `reasoning`. Duplicate `CONDITIONAL_SANITIZER` entries with similar bypass conditions are merged using fuzzy string matching (`fuzzywuzzy`, similarity threshold 80%).

---

### Stage 6 — Generate Project-Specific CodeQL Libraries
**File:** `utils/query_generator.py` → `generate_codeql_package_classification()` + `generate_conditional_sanitizer_library()`  
**Output:** `codeql/project_specific/<project>/VulnerableMethodsClassification.qll`, `ConditionalSanitizers.qll`

Two `.qll` library files are generated from the classified methods:

**`VulnerableMethodsClassification.qll`**  
Contains CodeQL predicates `isVulnerableSource(call)`, `isVulnerableSink(call)`, `isVulnerablePropagator(call)`, and CWE-specific sink predicates (e.g. `isCWE89Sink`). Each predicate matches calls to the classified npm package methods using `DataFlow::moduleImport(packageName).getAMemberCall(methodName)`.

**`ConditionalSanitizers.qll`**  
For each `CONDITIONAL_SANITIZER` method, the LLM is asked to write a CodeQL predicate that detects when the sanitizer can be bypassed. The generated predicate is compiled against a dummy CodeQL database; if it fails, the compiler error and relevant RAG documentation are fed back to the LLM for up to **5 iterative correction rounds**. Successfully validated predicates are written into the library; failures fall back to a stub predicate.

---

### Stage 7 — Determine Which CWEs to Scan For
**File:** `utils/cwe_decider.py` → `cwes_to_check()`  
**Prompt template:** `utils/prompts.py` → `decide_cwes_prompt()`  
**Output:** In-memory list of integer CWE IDs (also implicitly stored via `methods_vulnerable.json`)

Two complementary strategies are combined:

1. **LLM-based:** The project's `README.md` and `package.json` are read and sent to Claude. The LLM infers which CWE categories are plausible for this type of application (e.g. a web API is likely susceptible to injection, XSS, SSRF).
2. **Advisory-based:** CWE IDs are extracted directly from the GitHub advisory data collected in Stage 4.

The final list is the **union** of both sources, deduplicated and sorted.

---

### Stage 8 — Generate & Iteratively Refine Vulnerability Queries
**File:** `utils/query_generator.py` → `refine_vulnerability_query()`  
**Prompt templates:** `utils/prompts.py` → `sink_explaination_prompt`, `sink_implementation_prompt`, `sink_refinement_prompt`, `flow_explaination_prompt`, `flow_implementation_prompt`, `flow_refinement_prompt`, `get_sink_selection_prompt`  
**RAG:** `vector_db/chroma_db/` (queried inside `_get_relevant_documentation()`)  
**Output:** `codeql/project_specific/<project>/CWE-<id>.ql`

For each CWE in the list from Stage 7, a `@kind path-problem` CodeQL query is assembled and refined in two phases:

**Phase A — Sink Refinement**
The LLM is asked to (1) explain what sink patterns are missing for this CWE given the project's call graph, then (2) implement the missing sink predicates in QL. The generated code is compiled; on failure the error plus RAG-retrieved docs are fed back for up to 5 correction rounds.

**Phase B — Flow Refinement**
The LLM is asked to (1) explain what taint-flow steps might be missing (e.g. custom propagators), then (2) implement additional `isAdditionalFlowStep` predicates. Same compile-and-correct loop (up to 5 rounds).

The final query imports the project-specific libraries from Stage 6, the built-in `isSink.qll` / `isSource.qll` from `codeql/`, and any CWE compatibility bridges from `codeql/compat/` (checked via `codeql/registry.json`).

The call graph used to guide the LLM is extracted on demand via `codeql/extractCallGraph.ql` and filtered by CWE-relevant keywords (themselves suggested by the LLM) — see `utils/general.py` → `extract_call_graph()` + `format_call_graph_for_cwe()`.

---

### Stage 9 — Run Final Queries (Batch)
**File:** `utils/query_runner.py` → `run_codeql_queries_batch()` / `run_codeql_path_problem()`  
**Input:** `codeql/project_specific/<project>/` (generated queries) + `codeql/default/` (pre-written queries)  
**Output:** `output/<project>/batch_results.sarif`, `batch_results.csv`

All generated `.ql` queries are executed against the project's CodeQL database using `codeql database analyze`. Path-problem queries produce SARIF output (showing full source-to-sink taint-flow paths) and a parallel CSV for easier downstream processing. Queries run in parallel using all available CPU threads.

---

### Stage 10 — LLM False Positive Filtering
**File:** `utils/llm_filtering.py` → `filter_llm_findings()`  
**Prompt template:** `utils/prompts.py` → `get_vulnerability_confidence()`  
**Output:** `output/<project>/filtered_results.csv`, optionally `llm_responses.json`

For each raw finding from Stage 9, the surrounding source code is extracted:
- The **sink line** context is located using smart AST-based boundary detection (`utils/general.py` → `get_smart_context_range()`) which uses `esprima` to find the enclosing function or statement.
- The **source expression** and **sink expression** are extracted verbatim from the file.

This context, together with the query name and description, is sent to Claude which returns a JSON object with a `confidence` score (0–1), a `verdict`, and `reasoning`. Findings below the threshold (default **0.6**) are discarded as likely false positives.

Previously saved LLM responses can be re-filtered at different thresholds without re-invoking the LLM via `filter_with_existing_responses()`.

---

### Stage 11 — Evaluation Against Ground Truth
**Files:** `evaluation_cves/specific_evaluator.py`, `evaluation_cves/general_evaluator.py`, `vuln_apps_eval/analyze_results.py`, `vuln_apps_eval/filter_results.py`, `vuln_apps_eval/compare_results.py`, `results_process.py`  
**Ground truth:** `evaluation_cves/all/*.json` (200+ CVEs), `vuln_apps_eval/dvna/vulns.json`, `vuln_apps_eval/juice-shop/`

Two evaluation strategies:

**CVE-Based Evaluation** (`evaluation_cves/`)  
Each CVE JSON file contains the expected vulnerable file and line number. After the pipeline runs, results are checked to see if the correct location was detected. `specific_evaluator.py` additionally tracks per-project timing statistics for every LLM call and every CodeQL query, writing a detailed report to `output/reports/`.

**Vulnerable App Evaluation** (`vuln_apps_eval/`)  
Tests against intentionally vulnerable apps (DVNA with 14 known vulnerabilities, OWASP Juice Shop). `analyze_results.py` computes **Precision / Recall / F1** by comparing pipeline findings against the ground truth JSON. `compare_results.py` cross-compares results with Semgrep and njsscan. `figures.py` generates evaluation charts.

`results_process.py` can combine and deduplicate CSV result files from multiple runs before evaluation.

---

## Supporting Infrastructure

### Static CodeQL Queries & Libraries
| File | Purpose |
|---|---|
| `codeql/getPackageMethods.ql` | Extract npm dependency method calls (Stage 3) |
| `codeql/extractCallGraph.ql` | Extract function call relationships (Stage 8) |
| `codeql/getSources.ql` | Extract all taint sources from a database |
| `codeql/getSinks.ql` | Extract all taint sinks from a database |
| `codeql/isSource.qll` | Source definitions: HTTP inputs, env vars, file reads, etc. |
| `codeql/isSink.qll` | Sink definitions across 11 vulnerability categories |
| `codeql/helpers.qll` | Shared helper predicates |
| `codeql/compat/` | CWE compatibility bridge files (imported by generated queries) |
| `codeql/default/CWE-*/` | 100+ pre-written default queries organised by CWE |
| `codeql/registry.json` | Maps CWE IDs → query files + whether a compat layer exists |
| `codeql/qlpack.yml` | CodeQL pack config (declares dependency on `codeql/javascript-all`) |

### Utility Modules
| File | Purpose |
|---|---|
| `utils/LLM.py` | Unified LLM client (Ariadne API / Claude); tracks per-project token & timing stats |
| `utils/prompts.py` | All prompt templates used across the pipeline |
| `utils/general.py` | File context extraction, JS AST parsing (`esprima`), CWE API lookup, call-graph formatting |
| `utils/node_post_process.py` | Deduplication and context extraction for source/sink nodes from `getSources.ql` / `getSinks.ql` results |
| `utils/scraper.py` | Repo cloning and OWASP CWE code scraping |

---

## Data Flow Summary

```
CVE JSON files
      │
      ▼
[Stage 1] scraper.py ──────────────────────────► codebases/<project>/
      │
      ▼
[Stage 2] create_db.py ────────────────────────► databases/<project>/
      │
      ▼
[Stage 3] getPackageMethods.ql + query_runner ──► output/<project>/methods.json
      │
      ▼
[Stage 4] methods_post_process.py ─────────────► output/<project>/methods_vulnerable.json
      │                  ▲
      │           GitHub Advisories API
      ▼
[Stage 5] LLM.py + prompts.py ─────────────────► output/<project>/methods_vulnerable_classified.json
      │
      ▼
[Stage 6] query_generator.py ──────────────────► codeql/project_specific/<project>/*.qll
      │
      ▼
[Stage 7] cwe_decider.py + LLM ────────────────► [CWE list]
      │
      ▼
[Stage 8] query_generator.py + RAG ────────────► codeql/project_specific/<project>/CWE-*.ql
      │         ▲
      │   vector_db/chroma_db/
      ▼
[Stage 9] query_runner.py ─────────────────────► output/<project>/batch_results.{sarif,csv}
      │
      ▼
[Stage 10] llm_filtering.py ───────────────────► output/<project>/filtered_results.csv
      │
      ▼
[Stage 11] analyze_results.py ─────────────────► Precision / Recall / F1
```
