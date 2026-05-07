# Final Report — Command Trace & Bug Fixes

This document records the step-by-step conceptual execution trace of every command in `COMMANDS.md`, the bugs found during that trace, and the fixes applied.

---

## Trace Methodology

Each command was traced through the full call stack:
- env vars resolved → function called → internal paths built → downstream calls followed
- Every file read, file written, and function signature checked against the actual source

Assumed conditions: all env vars set, Ariadne reachable, CodeQL on PATH, source trees in place.

---

## Phase 1–4 — `evaluation.py`

### DVNA

```bash
PROJECT_NAME=dvna python3 vuln_apps_eval/evaluation.py
```

**Trace:**
1. `main()` reads `PROJECT_NAME=dvna`, `CODEBASE_SUBFOLDER=""` → `codebases_folder = <root>/codebases`
2. `process_single_project("dvna", codebases_folder, project_root, report_file, codebase_subfolder=None)`
3. `project_path = codebases/dvna` ✅ — directory exists
4. `create_codeql_database(project_path, response='n')` → output at `databases/dvna` (derived from `os.path.basename("codebases/dvna")`) ✅
5. `database_path = output/databases/dvna` ✅
6. CodeQL methods query → `output/dvna/methods.csv` ✅
7. `cwes_to_check("dvna", extra_folder=None)` → reads `codebases/dvna/README.md`, `codebases/dvna/package.json` ✅
8. `extract_call_graph(database_path, "dvna")` ✅
9. `refine_vulnerability_query(cwe_id, "dvna", extra_folder=None)` → reads same README/package.json paths ✅
10. Batch queries → `output/dvna_callgraphs1/dvna/batch_results.{sarif,csv}` ✅

**Result: ✅ PASSES**

---

### sgarden — backend

```bash
PROJECT_NAME=backend CODEBASE_SUBFOLDER=sgarden python3 vuln_apps_eval/evaluation.py
```

**Trace:**
1. `main()` reads `PROJECT_NAME=backend`, `CODEBASE_SUBFOLDER=sgarden` → `codebases_folder = <root>/codebases/sgarden`
2. `process_single_project("backend", codebases/sgarden, project_root, report_file, codebase_subfolder="sgarden")`
3. `project_path = codebases/sgarden/backend` ✅ — correct path
4. `create_codeql_database("codebases/sgarden/backend", response='n')`
   - `full_source_path` = absolute path to `codebases/sgarden/backend` ✅
   - `project_name = os.path.basename("codebases/sgarden/backend") = "backend"` ✅
   - `output_path = databases/backend` ✅
5. `database_path = databases/backend` ✅
6. `cwes_to_check("backend", extra_folder="sgarden")` → reads `codebases/sgarden/backend/README.md` ✅
7. `refine_vulnerability_query(cwe_id, "backend", extra_folder="sgarden")` → same README/package.json paths ✅
8. Batch output → `output/backend_callgraphs1/backend/batch_results.{sarif,csv}` ✅

**Result: ✅ PASSES**

---

### sgarden — frontend

```bash
PROJECT_NAME=frontend CODEBASE_SUBFOLDER=sgarden python3 vuln_apps_eval/evaluation.py
```

**Trace:** Identical structure to backend with `frontend` substituted. All paths resolve correctly.

**Result: ✅ PASSES**

---

## Phase 5 — `filter_results.py`

### Bug found and fixed during trace

**Bug (introduced by our rewrite):** The original `filter_results.py` (pre-session) used `deduplicated.csv` as input to `filter_llm_findings`. Our rewrite changed it to `batch_results.csv`. This is wrong for two reasons:

1. `batch_results.csv` from `run_codeql_queries_batch` contains **one row per query result per query file** — if the same vulnerability is found by multiple queries, it appears multiple times. `filter_llm_findings` would call the LLM for every duplicate, wasting calls and producing inconsistent scores.
2. The original pipeline (per `PIPELINE_MAP.md` Stage 9→10) passes results through `results_process.py` which produces `deduplicated.csv` (deduped on columns `[4, 5, 7]` = file, source_line, sink_line) before filtering.

**Fix applied:** `filter_results.py` now inlines the deduplication step (same logic as `results_process.py`, scoped to the single project's results dir) before calling `filter_llm_findings`, and uses `deduplicated.csv` as input. `results_process.py` no longer needs to be run separately.

---

### Bug found and fixed during trace

**Bug (pre-existing, exposed by our subfolder work):** `get_smart_context_range` was designed to receive a **relative** path from CodeQL (e.g. `src/app.js`) and build the absolute path internally. However, `llm_filtering.py` builds the **absolute** path first and passes it to `get_smart_context_range`. The function then tried to join the absolute path again:

```python
# get_smart_context_range (before fix):
full_path = os.path.join(os.path.dirname(__file__), "..", "codebases", project_name, file_path.lstrip('/\\'))
# If file_path = "/repo/codebases/dvna/src/app.js"
# → lstrip gives: "repo/codebases/dvna/src/app.js"
# → result: "/repo/codebases/dvna/repo/codebases/dvna/src/app.js" ← WRONG
```

This was a latent bug in the original code. It happened to work only if the file didn't exist at the wrong path (the function would fall back to the `±15 lines` buffer), meaning AST parsing was silently skipped for every finding.

**Fix applied:** `get_smart_context_range` now checks `os.path.isabs(file_path)` first. If the path is already absolute (as built by `llm_filtering.py`), it is used directly. If relative, the original resolution logic applies. This makes the function correct in both call contexts.

---

### DVNA — Baseline

```bash
PROJECT_NAME=dvna OUTPUT_DIR=output python3 vuln_apps_eval/filter_results.py
```

**Trace:**
1. `_results_dir = output/dvna_callgraphs1/dvna`
2. `batch_csv = output/dvna_callgraphs1/dvna/batch_results.csv` — produced by Phase 4 ✅
3. **Dedup step:** `deduplicated.csv` does not exist → reads `batch_results.csv`, deduplicates on `[4,5,7]`, writes `deduplicated.csv` ✅
4. `response_cache = output/dvna_callgraphs1/dvna/llm_responses.json` — does not exist on first run
5. `filter_llm_findings("dvna", deduped_csv, filtered0_csv, threshold=0, response_output_path=cache, use_enriched_context=False, codebase_subfolder=None)`
   - For each row: `relative_path = row[4]`, `sink_line = row[7]`
   - `file_path = <root>/codebases/dvna/<relative_path>` (absolute) ✅
   - `get_smart_context_range(file_path, sink_line, ...)` → `os.path.isabs(file_path)` is True → uses `file_path` directly ✅
   - `extract_context_from_file(file_path, start, end, sink_line)` → uses absolute path directly ✅
   - LLM called, response saved ✅
6. Threshold sweep: `filter_with_existing_responses(deduped_csv, cache, filtered_T_csv, threshold=T)` × 8 ✅
7. All 8 filtered CSVs written ✅

**Result: ✅ PASSES**

---

### DVNA — Enriched

```bash
PROJECT_NAME=dvna OUTPUT_DIR=output ENRICHED_CONTEXT=1 python3 vuln_apps_eval/filter_results.py
```

**Trace:**
1. Same dedup step → `deduplicated.csv` already exists, skipped ✅
2. `response_cache = output/dvna_callgraphs1/dvna/llm_responses_enriched.json` — separate file ✅
3. `filter_llm_findings(..., use_enriched_context=True, ...)`
   - Per finding: `get_enriched_context(context, file_path, sink_line, query_name)` → LLM call → summary ✅
   - Summary passed to `get_vulnerability_confidence(..., enriched_summary=summary)` ✅
4. Sweep from enriched cache → 8 `*_enriched_deduplicated.csv` files ✅

**Result: ✅ PASSES**

---

### sgarden — backend (Baseline)

```bash
PROJECT_NAME=backend CODEBASE_SUBFOLDER=sgarden OUTPUT_DIR=output python3 vuln_apps_eval/filter_results.py
```

**Trace:**
1. `_results_dir = output/backend_callgraphs1/backend` ✅
2. Dedup step on `batch_results.csv` → `deduplicated.csv` ✅
3. `filter_llm_findings("backend", deduped_csv, ..., codebase_subfolder="sgarden")`
   - `file_path = <root>/codebases/sgarden/backend/<relative_path>` ✅
   - `get_smart_context_range(file_path, ...)` → absolute path detected → used directly ✅
4. Sweep → 8 filtered CSVs ✅

**Result: ✅ PASSES**

---

### sgarden — frontend (Baseline and Enriched)

Identical trace to backend with `frontend` substituted. All paths resolve correctly.

**Result: ✅ PASSES**

---

## Evaluate — `analyze_results.py`

### DVNA

```bash
GT=vuln_apps_eval/old/dvna/vulns.json
RD=output/dvna_callgraphs1/dvna
OD=vuln_apps_eval/dvna && mkdir -p $OD

python3 vuln_apps_eval/analyze_results.py $RD/filtered60_deduplicated.csv $GT $OD/results_T60.json
```

**Trace:**
1. `csv_file = output/dvna_callgraphs1/dvna/filtered60_deduplicated.csv` — produced by filter step ✅
2. `json_file = vuln_apps_eval/old/dvna/vulns.json` — exists ✅
3. `output_file = vuln_apps_eval/dvna/results_T60.json` — dir created by `mkdir -p` ✅
4. `load_csv` reads with `header=None`, expects `row[0]=name, row[4]=file, row[5]=source_line, row[7]=sink_line` — matches the format produced by `filter_with_existing_responses` (which writes `header=False, index=False`, preserving the original column structure) ✅
5. Ground truth schema `{challenge: {file, startLine, endLine, vulnLines: [...]}}` matches `load_json` ✅
6. Results JSON written ✅

**Result: ✅ PASSES**

---

### sgarden — backend

```bash
GT=vuln_apps_eval/old/sgarden-backend/vulns.json
RD=output/backend_callgraphs1/backend
OD=vuln_apps_eval/sgarden-backend && mkdir -p $OD
```

**Trace:** Same structure. Ground truth at `vuln_apps_eval/old/sgarden-backend/vulns.json` ✅. Output dir created ✅.

**Result: ✅ PASSES**

---

### sgarden — frontend

```bash
GT=vuln_apps_eval/old/sgarden-frontend/vulns.json
RD=output/frontend_callgraphs1/frontend
OD=vuln_apps_eval/sgarden-frontend && mkdir -p $OD
```

**Result: ✅ PASSES**

---

## Compare — `compare_results.py`

```bash
python3 vuln_apps_eval/compare_results.py \
    vuln_apps_eval/dvna/results_T75_enriched.json \
    vuln_apps_eval/dvna/results_T75.json \
    vuln_apps_eval/dvna/comparison_T75_enriched_vs_baseline.json
```

**Trace:**
1. Both input JSONs produced by `analyze_results.py` in the evaluate step ✅
2. `load_results` reads JSON, extracts `true_positives` list ✅
3. `get_tp_key(tp)` uses `(tp['file'], tp['sink_line'])` — both fields present in analyze output ✅
4. Output JSON written ✅

**Result: ✅ PASSES**

---

## Summary of All Bugs Found and Fixed

| # | Location | Bug | Fix |
|---|---|---|---|
| 1 | `filter_results.py` | Used `batch_results.csv` directly as LLM input — skipping deduplication, causing duplicate LLM calls and inconsistent scores | Added inline dedup step (reads `batch_results.csv`, deduplicates on `[file, source_line, sink_line]`, writes `deduplicated.csv`); `filter_llm_findings` now receives `deduplicated.csv` |
| 2 | `utils/general.py` → `get_smart_context_range` | Received an absolute path from `llm_filtering.py` but tried to join it again with `codebases/<project>/...`, producing a nonsensical double-path. AST parsing silently fell back to ±15 line buffer for every finding | Added `os.path.isabs(file_path)` check: absolute paths are used directly; relative paths use the existing resolution logic |

---

## No Other Issues Found

All other paths, function signatures, env var flows, column indices, and file dependencies trace correctly:

- `create_codeql_database` derives `project_name` from `os.path.basename(source_path)` → `backend` for sgarden ✅
- `cwes_to_check(extra_folder=codebase_subfolder)` and `refine_vulnerability_query(extra_folder=codebase_subfolder)` both resolve README/package.json at `codebases/sgarden/backend/` ✅
- `filter_with_existing_responses` writes `header=False, index=False` CSVs — same format as `batch_results.csv` — so `analyze_results.py` column indices `[0,4,5,7]` remain valid throughout the pipeline ✅
- `mkdir -p $OD` is present in every evaluate block for all three projects ✅
- Baseline and enriched cache files are separate (`llm_responses.json` vs `llm_responses_enriched.json`) — runs never overwrite each other ✅
- The threshold sweep runs automatically inside `filter_results.py` — no manual re-runs needed ✅
