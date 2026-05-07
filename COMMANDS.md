# Experiment Commands

All commands are run from the **repository root** (`/Users/giosiach/christoforidis-thesis`).

---

## Performance configuration

Three environment variables control CodeQL performance across the entire pipeline
(database creation, refinement queries, and batch execution).  Set them once in
your shell before running anything.

| Variable | What it controls | MacBook Air M4 (16 GB) | Legion R7-5800 (16 GB, Debian) |
|---|---|---|---|
| `CODEQL_RAM` | MB given to the CodeQL evaluator JVM heap | `10240` | `10240` |
| `CODEQL_DISK_CACHE` | MB for on-disk intermediate predicate cache | `4096` | `4096` |
| `CODEQL_THREADS` | Evaluator threads (`0` = all logical cores) | `0` (10 cores) | `0` (16 threads) |

The JS extractor automatically inherits `CODEQL_RAM` and `CODEQL_THREADS` via
`LGTM_TYPESCRIPT_RAM` and `LGTM_THREADS` — no extra config needed.

**Defaults (if unset):** `CODEQL_RAM=4096`, `CODEQL_DISK_CACHE=2048`, `CODEQL_THREADS=0`.
The pipeline runs correctly without setting anything; the values above just make it faster.

### MacBook Air M4

```bash
export CODEQL_RAM=10240
export CODEQL_DISK_CACHE=4096
export CODEQL_THREADS=0
```

### Lenovo Legion (Debian)

```bash
export CODEQL_RAM=10240
export CODEQL_DISK_CACHE=4096
export CODEQL_THREADS=0
```

> **Tip:** Add these to your `~/.bashrc` / `~/.zshrc` (or a `.env` file sourced
> at the top of each session) so you never have to think about them again.

---

## Pipeline overview

| Phase | Script | Runs once per project |
|---|---|---|
| 1–4 (pipeline) | `vuln_apps_eval/evaluation.py` | Yes — identical for both variants |
| 5 (filter + sweep) | `vuln_apps_eval/filter_results.py` | Once per variant (baseline / enriched) |
| Evaluate | `vuln_apps_eval/analyze_results.py` | Once per threshold per variant |
| Compare | `vuln_apps_eval/compare_results.py` | Once per threshold pair |

**Threshold sweep is automatic.** `filter_results.py` calls the LLM once (scoring all findings), caches the scores, then immediately produces filtered CSVs for every threshold in `[0, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.9]` from the cache — no extra LLM calls and no manual re-runs needed.

**Two experiment variants:**
- **Baseline** — standard AST-based context extraction (existing pipeline)
- **Enriched** — adds an LLM semantic-summary pre-pass per finding (`ENRICHED_CONTEXT=1`), implementing the §6 future extension for the ablation study

---

## Prerequisites

```bash
source .venv/bin/activate
codeql --version
python3 -c "from utils.LLM import LLMHandler; print(LLMHandler().check_connection())"

ls codebases/dvna
ls codebases/sgarden/backend
ls codebases/sgarden/frontend
```

---

## DVNA

### Phase 1–4 — Pipeline

```bash
PROJECT_NAME=dvna \
python3 vuln_apps_eval/evaluation.py
```

Outputs:
- `output/dvna/` — methods, libraries, project-specific CodeQL files
- `output/dvna_callgraphs1/dvna/batch_results.{sarif,csv}` — raw findings
- `output/reports/llm_evaluation_batch_<timestamp>.txt` — timing report

---

### Phase 5 — Baseline filter + full threshold sweep

```bash
PROJECT_NAME=dvna \
OUTPUT_DIR=output \
python3 vuln_apps_eval/filter_results.py
```

Produces (in `output/dvna_callgraphs1/dvna/`):
- `llm_responses.json` — cached confidence scores (one LLM call per finding)
- `filtered0_deduplicated.csv` through `filtered90_deduplicated.csv` — one CSV per threshold

---

### Phase 5 — Enriched filter + full threshold sweep (ablation)

```bash
PROJECT_NAME=dvna \
OUTPUT_DIR=output \
ENRICHED_CONTEXT=1 \
python3 vuln_apps_eval/filter_results.py
```

Produces (in `output/dvna_callgraphs1/dvna/`):
- `llm_responses_enriched.json` — separate cache (enriched summaries baked in)
- `filtered0_enriched_deduplicated.csv` through `filtered90_enriched_deduplicated.csv`

---

### Evaluate — Baseline

```bash
GT=vuln_apps_eval/old/dvna/vulns.json
RD=output/dvna_callgraphs1/dvna
OD=vuln_apps_eval/dvna && mkdir -p $OD

python3 vuln_apps_eval/analyze_results.py $RD/filtered0_deduplicated.csv  $GT $OD/results_T0.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered60_deduplicated.csv  $GT $OD/results_T60.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered75_deduplicated.csv  $GT $OD/results_T75.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered80_deduplicated.csv  $GT $OD/results_T80.json
```

### Evaluate — Enriched (ablation)

```bash
GT=vuln_apps_eval/old/dvna/vulns.json
RD=output/dvna_callgraphs1/dvna
OD=vuln_apps_eval/dvna && mkdir -p $OD

python3 vuln_apps_eval/analyze_results.py $RD/filtered0_enriched_deduplicated.csv  $GT $OD/results_T0_enriched.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered60_enriched_deduplicated.csv  $GT $OD/results_T60_enriched.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered75_enriched_deduplicated.csv  $GT $OD/results_T75_enriched.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered80_enriched_deduplicated.csv  $GT $OD/results_T80_enriched.json
```

### Compare baseline vs. enriched at T=0.75

```bash
python3 vuln_apps_eval/compare_results.py \
    vuln_apps_eval/dvna/results_T75_enriched.json \
    vuln_apps_eval/dvna/results_T75.json \
    vuln_apps_eval/dvna/comparison_T75_enriched_vs_baseline.json
```

---

---

## sgarden — backend

Source lives at `codebases/sgarden/backend`.
`CODEBASE_SUBFOLDER=sgarden` tells the pipeline to look there.
`PROJECT_NAME=backend` is the leaf folder name (used for all output naming).

### Phase 1–4 — Pipeline

```bash
PROJECT_NAME=backend \
CODEBASE_SUBFOLDER=sgarden \
python3 vuln_apps_eval/evaluation.py
```

Outputs:
- `output/backend/` — methods, libraries
- `output/backend_callgraphs1/backend/batch_results.{sarif,csv}`
- `output/reports/llm_evaluation_batch_<timestamp>.txt`

---

### Phase 5 — Baseline filter + full threshold sweep

```bash
PROJECT_NAME=backend \
CODEBASE_SUBFOLDER=sgarden \
OUTPUT_DIR=output \
python3 vuln_apps_eval/filter_results.py
```

Produces (in `output/backend_callgraphs1/backend/`):
- `llm_responses.json`
- `filtered0_deduplicated.csv` through `filtered90_deduplicated.csv`

---

### Phase 5 — Enriched filter + full threshold sweep (ablation)

```bash
PROJECT_NAME=backend \
CODEBASE_SUBFOLDER=sgarden \
OUTPUT_DIR=output \
ENRICHED_CONTEXT=1 \
python3 vuln_apps_eval/filter_results.py
```

Produces:
- `llm_responses_enriched.json`
- `filtered0_enriched_deduplicated.csv` through `filtered90_enriched_deduplicated.csv`

---

### Evaluate — Baseline

```bash
GT=vuln_apps_eval/old/sgarden-backend/vulns.json
RD=output/backend_callgraphs1/backend
OD=vuln_apps_eval/sgarden-backend && mkdir -p $OD

python3 vuln_apps_eval/analyze_results.py $RD/filtered0_deduplicated.csv  $GT $OD/results_T0.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered60_deduplicated.csv  $GT $OD/results_T60.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered75_deduplicated.csv  $GT $OD/results_T75.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered80_deduplicated.csv  $GT $OD/results_T80.json
```

### Evaluate — Enriched (ablation)

```bash
GT=vuln_apps_eval/old/sgarden-backend/vulns.json
RD=output/backend_callgraphs1/backend
OD=vuln_apps_eval/sgarden-backend && mkdir -p $OD

python3 vuln_apps_eval/analyze_results.py $RD/filtered0_enriched_deduplicated.csv  $GT $OD/results_T0_enriched.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered60_enriched_deduplicated.csv  $GT $OD/results_T60_enriched.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered75_enriched_deduplicated.csv  $GT $OD/results_T75_enriched.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered80_enriched_deduplicated.csv  $GT $OD/results_T80_enriched.json
```

### Compare baseline vs. enriched at T=0.75

```bash
python3 vuln_apps_eval/compare_results.py \
    vuln_apps_eval/sgarden-backend/results_T75_enriched.json \
    vuln_apps_eval/sgarden-backend/results_T75.json \
    vuln_apps_eval/sgarden-backend/comparison_T75_enriched_vs_baseline.json
```

---

---

## sgarden — frontend

Source lives at `codebases/sgarden/frontend`.

### Phase 1–4 — Pipeline

```bash
PROJECT_NAME=frontend \
CODEBASE_SUBFOLDER=sgarden \
python3 vuln_apps_eval/evaluation.py
```

---

### Phase 5 — Baseline filter + full threshold sweep

```bash
PROJECT_NAME=frontend \
CODEBASE_SUBFOLDER=sgarden \
OUTPUT_DIR=output \
python3 vuln_apps_eval/filter_results.py
```

---

### Phase 5 — Enriched filter + full threshold sweep (ablation)

```bash
PROJECT_NAME=frontend \
CODEBASE_SUBFOLDER=sgarden \
OUTPUT_DIR=output \
ENRICHED_CONTEXT=1 \
python3 vuln_apps_eval/filter_results.py
```

---

### Evaluate — Baseline

```bash
GT=vuln_apps_eval/old/sgarden-frontend/vulns.json
RD=output/frontend_callgraphs1/frontend
OD=vuln_apps_eval/sgarden-frontend && mkdir -p $OD

python3 vuln_apps_eval/analyze_results.py $RD/filtered0_deduplicated.csv  $GT $OD/results_T0.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered60_deduplicated.csv  $GT $OD/results_T60.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered75_deduplicated.csv  $GT $OD/results_T75.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered80_deduplicated.csv  $GT $OD/results_T80.json
```

### Evaluate — Enriched (ablation)

```bash
GT=vuln_apps_eval/old/sgarden-frontend/vulns.json
RD=output/frontend_callgraphs1/frontend
OD=vuln_apps_eval/sgarden-frontend && mkdir -p $OD

python3 vuln_apps_eval/analyze_results.py $RD/filtered0_enriched_deduplicated.csv  $GT $OD/results_T0_enriched.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered60_enriched_deduplicated.csv  $GT $OD/results_T60_enriched.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered75_enriched_deduplicated.csv  $GT $OD/results_T75_enriched.json
python3 vuln_apps_eval/analyze_results.py $RD/filtered80_enriched_deduplicated.csv  $GT $OD/results_T80_enriched.json
```

### Compare baseline vs. enriched at T=0.75

```bash
python3 vuln_apps_eval/compare_results.py \
    vuln_apps_eval/sgarden-frontend/results_T75_enriched.json \
    vuln_apps_eval/sgarden-frontend/results_T75.json \
    vuln_apps_eval/sgarden-frontend/comparison_T75_enriched_vs_baseline.json
```

---

---

## Output structure (after a full run)

```
codebases/
├── dvna/
└── sgarden/
    ├── backend/
    └── frontend/

output/
├── reports/
│   └── llm_evaluation_batch_<timestamp>.txt
├── <project_name>/                          # dvna | backend | frontend
│   ├── methods/
│   ├── methods_vulnerable.json
│   └── methods_vulnerable_classified.json
└── <project_name>_callgraphs1/
    └── <project_name>/
        ├── batch_results.{sarif,csv}        # Phase 4 raw findings
        ├── llm_responses.json               # baseline LLM cache
        ├── llm_responses_enriched.json      # enriched LLM cache
        ├── filtered0_deduplicated.csv       # no filter (recall ceiling)
        ├── filtered40_deduplicated.csv
        ├── filtered50_deduplicated.csv
        ├── filtered60_deduplicated.csv      # thesis default
        ├── filtered70_deduplicated.csv
        ├── filtered75_deduplicated.csv      # best F1 in thesis
        ├── filtered80_deduplicated.csv      # high-precision mode
        ├── filtered90_deduplicated.csv
        └── filtered*_enriched_*.csv         # enriched variants of the above

vuln_apps_eval/
├── dvna/
│   ├── results_T0.json … results_T80.json
│   ├── results_T0_enriched.json … results_T80_enriched.json
│   └── comparison_T75_enriched_vs_baseline.json
├── sgarden-backend/   (same structure)
└── sgarden-frontend/  (same structure)
```

---

## Threshold reference

| Threshold | Tag | Use case |
|---|---|---|
| 0 | `T0` | Recall ceiling — no filtering, all raw findings |
| 0.6 | `T60` | Thesis default — balanced precision/recall |
| 0.75 | `T75` | Best F1 in thesis experiments |
| 0.8 | `T80` | High-precision mode — fewer findings to review manually |
