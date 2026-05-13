# SGarden Experiment Walkthrough

Full end-to-end walkthrough for running all three model experiments (Haiku, Sonnet, Opus)
plus enriched-context variants on the SGarden backend.

All commands run from the repo root: `/Users/giosiach/christoforidis-thesis`

---

## 0. One-Time Setup: Clone SGarden

```bash
mkdir -p codebases/sgarden

git clone <SGARDEN_REPO_URL> codebases/sgarden/backend
cd codebases/sgarden/backend
git checkout <VULNERABLE_COMMIT_HASH>
cd /Users/giosiach/christoforidis-thesis
```

Verify:
```bash
ls codebases/sgarden/backend
```

---

## Experiment 1: SGarden × Haiku

### 1.1 Set model in `.env`
```
ARIADNE_MODEL_ID=claude-haiku-4-5-20251001
```

### 1.2 Run the pipeline (Phases 1–4)
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
.venv/bin/python3 vuln_apps_eval/evaluation.py
```

### 1.3 Run FP filtering — baseline
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py
```

### 1.4 Compute metrics for all thresholds
```bash
GT="vuln_apps_eval/old/sgarden-backend/vulns.json"
RESULTS_DIR="output/backend_callgraphs1/backend"
OUT="experiments/sgarden-haiku/results" && mkdir -p "$OUT"

for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_deduplicated.csv" \
        "$GT" \
        "$OUT/results_T${T}.json"
done
```

### 1.5 Save results
```bash
EXP="experiments/sgarden-haiku"
mkdir -p "$EXP/output" "$EXP/codeql_queries" "$EXP/report"
cp -r output/backend_callgraphs1 "$EXP/output/"
cp -r output/backend "$EXP/output/"
cp -r codeql/project_specific/backend "$EXP/codeql_queries/"
cp "$(ls -t output/reports/llm_evaluation_batch_*.txt | head -1)" "$EXP/report/report.txt"
```

### 1.6 Run enriched context variant (before cleanup)
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
OUTPUT_DIR="$(pwd)/output" ENRICHED_CONTEXT=1 \
.venv/bin/python3 vuln_apps_eval/filter_results.py

OUT="experiments/sgarden-haiku-enriched/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_enriched_deduplicated.csv" \
        "$GT" \
        "$OUT/results_T${T}.json"
done

mkdir -p experiments/sgarden-haiku-enriched/output
cp -r output/backend_callgraphs1 experiments/sgarden-haiku-enriched/output/
```

### 1.7 Cleanup before Sonnet
```bash
# Delete model-specific outputs only
# DO NOT delete: databases/backend/  codeql/project_specific/backend/
rm -rf output/backend_callgraphs1 output/backend
```

---

## Experiment 2: SGarden × Sonnet

### 2.1 Set model in `.env`
```
ARIADNE_MODEL_ID=claude-sonnet-4-6
```

### 2.2 Run the pipeline
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
.venv/bin/python3 vuln_apps_eval/evaluation.py
```

### 2.3 FP filtering — baseline
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py
```

### 2.4 Metrics
```bash
GT="vuln_apps_eval/old/sgarden-backend/vulns.json"
RESULTS_DIR="output/backend_callgraphs1/backend"
OUT="experiments/sgarden-sonnet/results" && mkdir -p "$OUT"

for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_deduplicated.csv" \
        "$GT" \
        "$OUT/results_T${T}.json"
done
```

### 2.5 Save
```bash
EXP="experiments/sgarden-sonnet"
mkdir -p "$EXP/output" "$EXP/codeql_queries" "$EXP/report"
cp -r output/backend_callgraphs1 "$EXP/output/"
cp -r output/backend "$EXP/output/"
cp -r codeql/project_specific/backend "$EXP/codeql_queries/"
cp "$(ls -t output/reports/llm_evaluation_batch_*.txt | head -1)" "$EXP/report/report.txt"
```

### 2.6 Enriched variant
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
OUTPUT_DIR="$(pwd)/output" ENRICHED_CONTEXT=1 \
.venv/bin/python3 vuln_apps_eval/filter_results.py

OUT="experiments/sgarden-sonnet-enriched/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_enriched_deduplicated.csv" \
        "$GT" \
        "$OUT/results_T${T}.json"
done

mkdir -p experiments/sgarden-sonnet-enriched/output
cp -r output/backend_callgraphs1 experiments/sgarden-sonnet-enriched/output/
```

### 2.7 Cleanup
```bash
rm -rf output/backend_callgraphs1 output/backend
```

---

## Experiment 3: SGarden × Opus

### 3.1 Set model in `.env`
```
ARIADNE_MODEL_ID=claude-opus-4-6@default
```

### 3.2 Run the pipeline
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
.venv/bin/python3 vuln_apps_eval/evaluation.py
```

### 3.3 FP filtering — baseline
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py
```

### 3.4 Metrics
```bash
GT="vuln_apps_eval/old/sgarden-backend/vulns.json"
RESULTS_DIR="output/backend_callgraphs1/backend"
OUT="experiments/sgarden-opus/results" && mkdir -p "$OUT"

for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_deduplicated.csv" \
        "$GT" \
        "$OUT/results_T${T}.json"
done
```

### 3.5 Save
```bash
EXP="experiments/sgarden-opus"
mkdir -p "$EXP/output" "$EXP/codeql_queries" "$EXP/report"
cp -r output/backend_callgraphs1 "$EXP/output/"
cp -r output/backend "$EXP/output/"
cp -r codeql/project_specific/backend "$EXP/codeql_queries/"
cp "$(ls -t output/reports/llm_evaluation_batch_*.txt | head -1)" "$EXP/report/report.txt"
```

### 3.6 Enriched variant
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
OUTPUT_DIR="$(pwd)/output" ENRICHED_CONTEXT=1 \
.venv/bin/python3 vuln_apps_eval/filter_results.py

OUT="experiments/sgarden-opus-enriched/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_enriched_deduplicated.csv" \
        "$GT" \
        "$OUT/results_T${T}.json"
done

mkdir -p experiments/sgarden-opus-enriched/output
cp -r output/backend_callgraphs1 experiments/sgarden-opus-enriched/output/
```

### 3.7 Final cleanup — all SGarden done
```bash
rm -rf output/backend_callgraphs1 output/backend
rm -rf databases/backend codeql/project_specific/backend
```

---

## What gets saved

After all 3 experiments + enriched variants, `experiments/` will contain:

```
experiments/
├── sgarden-haiku/
│   ├── output/backend_callgraphs1/   ← batch results + filtered CSVs + llm_responses.json
│   ├── output/backend/               ← methods*.json
│   ├── codeql_queries/backend/       ← generated .qll + CWE-*_final_claude-haiku-*.ql
│   ├── report/report.txt             ← timing report
│   └── results/                      ← results_T{0..90}.json
├── sgarden-haiku-enriched/
│   ├── output/backend_callgraphs1/   ← llm_responses_enriched.json + enriched CSVs
│   └── results/
├── sgarden-sonnet/          (same structure)
├── sgarden-sonnet-enriched/ (same structure)
├── sgarden-opus/            (same structure)
└── sgarden-opus-enriched/   (same structure)
```
