# Multi-Model Experiment Commands

## Experiment Matrix

| Experiment | Project | Model | Embedder |
|---|---|---|---|
| dvna-haiku | DVNA | claude-haiku-4-5-20251001 | BAAI/bge-base-en-v1.5 |
| dvna-sonnet | DVNA | claude-sonnet-4-6 | BAAI/bge-base-en-v1.5 |
| dvna-opus | DVNA | claude-opus-4-6@default | BAAI/bge-base-en-v1.5 |
| sgarden-haiku | SGarden backend | claude-haiku-4-5-20251001 | BAAI/bge-base-en-v1.5 |
| sgarden-sonnet | SGarden backend | claude-sonnet-4-6 | BAAI/bge-base-en-v1.5 |
| sgarden-opus | SGarden backend | claude-opus-4-6@default | BAAI/bge-base-en-v1.5 |

Plus enriched-context variants for each (ENRICHED_CONTEXT=1, Phase 5 only).

---

## Prerequisites (one-time, already done)

- [x] ChromaDB built with BGE embedder → `vector_db/chroma_db/`
- [x] ChromaDB saved → `experiments/chroma_db_bge/`
- [x] DVNA cloned → `codebases/dvna/`
- [ ] SGarden cloned → `codebases/sgarden/backend/`

### `.env` must contain:
```
CODEQL_BIN="/Users/giosiach/.local/codeql/codeql"
EMBEDDING_MODEL="BAAI/bge-base-en-v1.5"
EMBEDDING_DEVICE="mps"
CODEQL_RAM=10240
CODEQL_DISK_CACHE=4096
```

### Always use `.venv/bin/python3`
The system `python3` is Homebrew Python 3.13 (outside the venv). All commands below use `.venv/bin/python3` explicitly.

---

## Results Structure

```
experiments/
├── chroma_db_bge/              ← shared ChromaDB (built once)
├── dvna-haiku/
│   ├── output/
│   │   ├── dvna/               ← methods*.json
│   │   └── dvna_callgraphs1/   ← batch_results.csv, filtered CSVs, llm_responses.json
│   ├── codeql_queries/dvna/    ← generated .qll and CWE-*_final_*.ql files
│   ├── report/report.txt       ← timing report
│   └── results/                ← results_T{0,40,50,60,70,75,80,90}.json
├── dvna-haiku-enriched/
│   ├── output/dvna_callgraphs1/ ← llm_responses_enriched.json, enriched filtered CSVs
│   └── results/
├── dvna-sonnet/
│   └── ...
└── ...
```

---

## Reuse Rules

| Artifact | Reusable across models? | Notes |
|---|---|---|
| `databases/<project>/` | ✅ Yes | Build once, reuse for all 3 models |
| `output/<project>/methods*.json` | ✅ Yes | Advisory matching is model-independent |
| `codeql/project_specific/*.qll` | ✅ Yes | Libraries from methods, not model-dependent |
| `codeql/project_specific/CWE-*_final_<model>.ql` | ⚠️ Per model | Named with model suffix — coexist safely |
| `output/<project>_callgraphs1/` | ❌ No | Delete before each new model run |
| `llm_responses.json` | ❌ No | Per model — delete with callgraphs1 |
| `llm_responses_enriched.json` | ❌ No | Per model/variant |

---

## EXPERIMENT 1: DVNA × Haiku

### Step 1 — Set model in `.env`
```
ARIADNE_MODEL_ID=claude-haiku-4-5-20251001
```

### Step 2 — Run main pipeline (Phases 1–4)
```bash
cd /Users/giosiach/christoforidis-thesis
PROJECT_NAME="dvna" .venv/bin/python3 vuln_apps_eval/evaluation.py
```
Expected time: **2–3 hours** (45 CWEs × ~2 min each + batch execution ~60 min)

### Step 3 — FP filtering (Phase 5, baseline)
```bash
PROJECT_NAME="dvna" OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py
```
Expected time: **10–15 min**

### Step 4 — Metrics for all thresholds
```bash
GT="vuln_apps_eval/old/dvna/vulns.json"
RESULTS_DIR="output/dvna_callgraphs1/dvna"
OUT="experiments/dvna-haiku/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done
```

### Step 5 — Save results
```bash
EXP="experiments/dvna-haiku" && mkdir -p "$EXP/output" "$EXP/codeql_queries" "$EXP/report"
cp -r output/dvna_callgraphs1 "$EXP/output/"
cp -r output/dvna "$EXP/output/"
cp -r codeql/project_specific/dvna "$EXP/codeql_queries/"
cp "$(ls -t output/reports/llm_evaluation_batch_*.txt | head -1)" "$EXP/report/report.txt"
echo "Saved to $EXP"
```

### Step 6 — Enriched context variant (Phase 5 only)
> Run this BEFORE cleanup (Step 7) so you don't need to restore files.
```bash
ENRICHED_CONTEXT=1 PROJECT_NAME="dvna" OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py

GT="vuln_apps_eval/old/dvna/vulns.json"
RESULTS_DIR="output/dvna_callgraphs1/dvna"
OUT="experiments/dvna-haiku-enriched/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_enriched_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done
mkdir -p experiments/dvna-haiku-enriched/output
cp -r output/dvna_callgraphs1 experiments/dvna-haiku-enriched/output/
```

### Step 7 — Cleanup before Sonnet
```bash
# Delete model-specific outputs — keep databases/ and project_specific/!
rm -rf output/dvna_callgraphs1 output/dvna
```

---

## EXPERIMENT 2: DVNA × Sonnet

### Step 1 — Set model in `.env`
```
ARIADNE_MODEL_ID=claude-sonnet-4-6
```

### Steps 2–7
```bash
PROJECT_NAME="dvna" .venv/bin/python3 vuln_apps_eval/evaluation.py

PROJECT_NAME="dvna" OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py

GT="vuln_apps_eval/old/dvna/vulns.json"
RESULTS_DIR="output/dvna_callgraphs1/dvna"
OUT="experiments/dvna-sonnet/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done

EXP="experiments/dvna-sonnet" && mkdir -p "$EXP/output" "$EXP/codeql_queries" "$EXP/report"
cp -r output/dvna_callgraphs1 "$EXP/output/"
cp -r output/dvna "$EXP/output/"
cp -r codeql/project_specific/dvna "$EXP/codeql_queries/"
cp "$(ls -t output/reports/llm_evaluation_batch_*.txt | head -1)" "$EXP/report/report.txt"

# Enriched
ENRICHED_CONTEXT=1 PROJECT_NAME="dvna" OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py
OUT="experiments/dvna-sonnet-enriched/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_enriched_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done
mkdir -p experiments/dvna-sonnet-enriched/output
cp -r output/dvna_callgraphs1 experiments/dvna-sonnet-enriched/output/

# Cleanup (keep databases/dvna! keep project_specific/dvna!)
rm -rf output/dvna_callgraphs1 output/dvna
```

---

## EXPERIMENT 3: DVNA × Opus

### Step 1 — Set model in `.env`
```
ARIADNE_MODEL_ID=claude-opus-4-6@default
```

### Steps 2–7
```bash
PROJECT_NAME="dvna" .venv/bin/python3 vuln_apps_eval/evaluation.py

PROJECT_NAME="dvna" OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py

GT="vuln_apps_eval/old/dvna/vulns.json"
RESULTS_DIR="output/dvna_callgraphs1/dvna"
OUT="experiments/dvna-opus/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done

EXP="experiments/dvna-opus" && mkdir -p "$EXP/output" "$EXP/codeql_queries" "$EXP/report"
cp -r output/dvna_callgraphs1 "$EXP/output/"
cp -r output/dvna "$EXP/output/"
cp -r codeql/project_specific/dvna "$EXP/codeql_queries/"
cp "$(ls -t output/reports/llm_evaluation_batch_*.txt | head -1)" "$EXP/report/report.txt"

# Enriched
ENRICHED_CONTEXT=1 PROJECT_NAME="dvna" OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py
OUT="experiments/dvna-opus-enriched/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_enriched_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done
mkdir -p experiments/dvna-opus-enriched/output
cp -r output/dvna_callgraphs1 experiments/dvna-opus-enriched/output/

# Final DVNA cleanup — now safe to delete database too
rm -rf output/dvna_callgraphs1 output/dvna
rm -rf databases/dvna codeql/project_specific/dvna
```

---

## SGarden Setup (one-time before SGarden experiments)

```bash
mkdir -p codebases/sgarden
git clone <SGARDEN_REPO_URL> codebases/sgarden/backend
cd codebases/sgarden/backend && git checkout <VULNERABLE_COMMIT_HASH>
cd /Users/giosiach/christoforidis-thesis
```

> Check `COMMANDS.md` or `vuln_apps_eval/old/sgarden-backend/` for the repo URL and commit.

---

## EXPERIMENT 4: SGarden × Haiku

### Step 1 — Set model in `.env`
```
ARIADNE_MODEL_ID=claude-haiku-4-5-20251001
```

### Steps 2–7
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
.venv/bin/python3 vuln_apps_eval/evaluation.py

PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py

GT="vuln_apps_eval/old/sgarden-backend/vulns.json"
RESULTS_DIR="output/backend_callgraphs1/backend"
OUT="experiments/sgarden-haiku/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done

EXP="experiments/sgarden-haiku" && mkdir -p "$EXP/output" "$EXP/codeql_queries" "$EXP/report"
cp -r output/backend_callgraphs1 "$EXP/output/"
cp -r output/backend "$EXP/output/"
cp -r codeql/project_specific/backend "$EXP/codeql_queries/"
cp "$(ls -t output/reports/llm_evaluation_batch_*.txt | head -1)" "$EXP/report/report.txt"

# Enriched
ENRICHED_CONTEXT=1 PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
OUTPUT_DIR="$(pwd)/output" .venv/bin/python3 vuln_apps_eval/filter_results.py
OUT="experiments/sgarden-haiku-enriched/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_enriched_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done
mkdir -p experiments/sgarden-haiku-enriched/output
cp -r output/backend_callgraphs1 experiments/sgarden-haiku-enriched/output/

# Cleanup (keep databases/backend! keep project_specific/backend!)
rm -rf output/backend_callgraphs1 output/backend
```

---

## EXPERIMENT 5: SGarden × Sonnet

### Step 1 — Set model in `.env`
```
ARIADNE_MODEL_ID=claude-sonnet-4-6
```

### Steps 2–7
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
.venv/bin/python3 vuln_apps_eval/evaluation.py

PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py

GT="vuln_apps_eval/old/sgarden-backend/vulns.json"
RESULTS_DIR="output/backend_callgraphs1/backend"
OUT="experiments/sgarden-sonnet/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done

EXP="experiments/sgarden-sonnet" && mkdir -p "$EXP/output" "$EXP/codeql_queries" "$EXP/report"
cp -r output/backend_callgraphs1 "$EXP/output/"
cp -r output/backend "$EXP/output/"
cp -r codeql/project_specific/backend "$EXP/codeql_queries/"
cp "$(ls -t output/reports/llm_evaluation_batch_*.txt | head -1)" "$EXP/report/report.txt"

ENRICHED_CONTEXT=1 PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
OUTPUT_DIR="$(pwd)/output" .venv/bin/python3 vuln_apps_eval/filter_results.py
OUT="experiments/sgarden-sonnet-enriched/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_enriched_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done
mkdir -p experiments/sgarden-sonnet-enriched/output
cp -r output/backend_callgraphs1 experiments/sgarden-sonnet-enriched/output/

rm -rf output/backend_callgraphs1 output/backend
```

---

## EXPERIMENT 6: SGarden × Opus

### Step 1 — Set model in `.env`
```
ARIADNE_MODEL_ID=claude-opus-4-6@default
```

### Steps 2–7
```bash
PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
.venv/bin/python3 vuln_apps_eval/evaluation.py

PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" OUTPUT_DIR="$(pwd)/output" \
.venv/bin/python3 vuln_apps_eval/filter_results.py

GT="vuln_apps_eval/old/sgarden-backend/vulns.json"
RESULTS_DIR="output/backend_callgraphs1/backend"
OUT="experiments/sgarden-opus/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done

EXP="experiments/sgarden-opus" && mkdir -p "$EXP/output" "$EXP/codeql_queries" "$EXP/report"
cp -r output/backend_callgraphs1 "$EXP/output/"
cp -r output/backend "$EXP/output/"
cp -r codeql/project_specific/backend "$EXP/codeql_queries/"
cp "$(ls -t output/reports/llm_evaluation_batch_*.txt | head -1)" "$EXP/report/report.txt"

ENRICHED_CONTEXT=1 PROJECT_NAME="backend" CODEBASE_SUBFOLDER="sgarden" \
OUTPUT_DIR="$(pwd)/output" .venv/bin/python3 vuln_apps_eval/filter_results.py
OUT="experiments/sgarden-opus-enriched/results" && mkdir -p "$OUT"
for T in 0 40 50 60 70 75 80 90; do
    .venv/bin/python3 vuln_apps_eval/analyze_results.py \
        "$RESULTS_DIR/filtered${T}_enriched_deduplicated.csv" "$GT" "$OUT/results_T${T}.json"
done
mkdir -p experiments/sgarden-opus-enriched/output
cp -r output/backend_callgraphs1 experiments/sgarden-opus-enriched/output/

# Final cleanup — all SGarden done
rm -rf output/backend_callgraphs1 output/backend
rm -rf databases/backend codeql/project_specific/backend
```

---

## Thresholds Reference

All experiments sweep: `0, 40, 50, 60, 70, 75, 80, 90`

Thesis best result: **T=75**, F1=52.46% (DVNA, Sonnet, MiniLM embedder).

---

## Important Notes

### ⚠️ Haiku model ID
Verify the Ariadne model ID before running:
```bash
ARIADNE_MODEL_ID=claude-haiku-4-5-20251001 .venv/bin/python3 utils/LLM.py
```

### ✅ Database reuse across models
`databases/<project>/` is model-independent. Build once (first model), reuse for all three.
Delete only after all 3 models for that project are done.

### ✅ project_specific/ reuse across models
Generated `.qll` files are model-independent.
Generated `CWE-*_final_<model>.ql` files are named per-model — they coexist safely.
**Never delete `codeql/project_specific/<project>/` between models.**

### ❌ Always delete output/<project>_callgraphs1/ between models
If it exists, `filter_results.py` will reuse the cached `llm_responses.json` from the previous model.
Always save first (Step 5), then delete.

### ✅ Run enriched BEFORE cleanup
Enriched context (Step 6) reads from the same `output/dvna_callgraphs1/` as the baseline.
Run it immediately after Step 5, before Step 7 cleanup.

### ✅ CODEQL_RAM and CODEQL_DISK_CACHE
Set in `.env` to 10240 and 4096. Gives CodeQL 10GB heap.
Critical for batch execution of 45+ queries — cuts time from 60–90 min to 20–30 min.
