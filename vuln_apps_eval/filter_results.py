"""
Phase 5 — LLM false-positive filtering.

Workflow:
  1. Run results_process.py logic to combine and deduplicate the batch CSVs
     produced by Phase 4 (batch_results.csv → deduplicated.csv).
  2. First run: call the LLM for every finding and cache all confidence scores.
  3. Sweep the full threshold range [0, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.9]
     from the cache — no extra LLM calls needed for the precision-recall curve.

On subsequent runs (cache already exists), step 2 is skipped and the sweep
runs immediately from the cache.

Environment variables
---------------------
PROJECT_NAME        Project directory name inside codebases/ (default: dvna)
CODEBASE_SUBFOLDER  Optional parent folder inside codebases/ (e.g. "sgarden"
                    for codebases/sgarden/backend). Leave unset for top-level
                    projects like dvna.
OUTPUT_DIR          Root output directory (default: current working directory)
ENRICHED_CONTEXT    Set to "1" to enable LLM semantic-summary enrichment
                    (ablation study variant, §6 of the thesis). Doubles the
                    number of LLM calls in this phase. Default: disabled.
"""

import sys
import os
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.llm_filtering import filter_llm_findings, filter_with_existing_responses

# ── Configuration ──────────────────────────────────────────────────────────────

project_name       = os.environ.get("PROJECT_NAME", "dvna")
codebase_subfolder = os.environ.get("CODEBASE_SUBFOLDER", "").strip() or None

# Ablation study flag: set ENRICHED_CONTEXT=1 to enable the LLM-based semantic
# context enrichment (inline comments + naming conventions) described in §6.
# Leave unset (default) for the baseline experiment.
# Note: enabling this doubles the number of LLM calls in Phase 5.
use_enriched_context = os.environ.get("ENRICHED_CONTEXT", "0").strip() == "1"

# Base output directory
_output_dir = os.environ.get("OUTPUT_DIR") or os.getcwd()

# Separate cache files for baseline vs. enriched so runs never overwrite each other
_run_suffix = "_enriched" if use_enriched_context else ""

# Thresholds to produce filtered CSVs for (covers the full precision-recall curve)
THRESHOLDS = [0, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.9]

# ── Paths ──────────────────────────────────────────────────────────────────────

_results_dir    = os.path.join(_output_dir, f"{project_name}_callgraphs1", project_name)
batch_csv       = os.path.join(_results_dir, "batch_results.csv")
deduped_csv     = os.path.join(_results_dir, "deduplicated.csv")
response_cache  = os.path.join(_results_dir, f"llm_responses{_run_suffix}.json")

def _filtered_csv(threshold: float) -> str:
    t_str = str(int(threshold * 100)) if threshold > 0 else "0"
    return os.path.join(_results_dir, f"filtered{t_str}{_run_suffix}_deduplicated.csv")

# ── Step 1: Deduplicate batch results ─────────────────────────────────────────

print(f"[filter_results] project={project_name}"
      + (f"  subfolder={codebase_subfolder}" if codebase_subfolder else "")
      + f"  enriched={use_enriched_context}")

if not os.path.exists(deduped_csv):
    if not os.path.exists(batch_csv):
        print(f"[ERROR] batch_results.csv not found at: {batch_csv}")
        print("        Run Phase 4 (evaluation.py) first.")
        sys.exit(1)
    print(f"[dedup] Combining and deduplicating batch results...")
    df = pd.read_csv(batch_csv, header=None)
    deduped_df = df.drop_duplicates(subset=[4, 5, 7])
    deduped_df.to_csv(deduped_csv, index=False, header=False)
    print(f"[dedup] {len(df)} rows → {len(deduped_df)} after deduplication → {deduped_csv}")
else:
    print(f"[dedup] Using existing deduplicated.csv ({deduped_csv})")

# ── Step 2: LLM scoring (first run) or use cache ──────────────────────────────

if not os.path.exists(response_cache):
    print(f"[llm] No cached scores found — calling the LLM for every finding.")
    print(f"      Scores will be saved to: {response_cache}")
    # Use threshold=0 so every finding gets a score; we sweep all thresholds
    # from the cache below without any further LLM calls.
    filter_llm_findings(
        project_name,
        deduped_csv,
        _filtered_csv(0),          # threshold=0 → keep everything on first pass
        threshold=0,
        response_output_path=response_cache,
        use_enriched_context=use_enriched_context,
        codebase_subfolder=codebase_subfolder,
    )
    print(f"[llm] Scoring complete.")
else:
    print(f"[llm] Using cached scores from: {response_cache}")

# ── Step 3: Sweep all thresholds from cache ────────────────────────────────────

print(f"[sweep] Generating filtered CSVs for all thresholds...")
for t in THRESHOLDS:
    out = _filtered_csv(t)
    filter_with_existing_responses(deduped_csv, response_cache, out, threshold=t)
    label = f"T={t}" if t > 0 else "no filter"
    print(f"  [{label}] → {os.path.relpath(out)}")

print(f"\n[done] All threshold CSVs written to: {_results_dir}")
