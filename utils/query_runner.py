"""
CodeQL CLI wrapper for executing queries and decoding results.

Provides functions to run CodeQL queries against a database and convert
the output into usable formats (CSV, SARIF):

  - run_codeql_query_tables(): Run @kind table queries -> BQRS -> CSV
  - run_codeql_path_problem(): Run @kind path-problem queries -> SARIF + CSV
  - run_codeql_queries_batch(): Run multiple queries in parallel with threading

All functions return a tuple of (success_status, error_message, execution_time).

Performance design
------------------
Both target machines have 16 GB RAM and fast SSDs (M4 MacBook Air, Ryzen 7 Legion).

Memory budget (all commands):
  --ram 10240          10 GB for the CodeQL evaluator JVM heap.  Leaves ~6 GB
                       for the OS, Python process, and concurrent LLM calls.
  --max-disk-cache 4096  4 GB on-disk cache for intermediate predicate results.
                       Dramatically speeds up repeated runs on the same database
                       (e.g. the 5-round refinement loop) because shared
                       sub-predicates (dataflow, call graph) are computed once
                       and reused across queries.

Threading:
  --threads 0          Use one thread per logical CPU core.  CodeQL's evaluator
                       parallelises at the predicate level, so more threads
                       directly reduces wall-clock time for taint-tracking
                       queries.  The JS extractor also picks this up via the
                       CODEQL_THREADS env var.

JVM stack:
  -J=-Xss64m           Deep taint-tracking recursion in the JavaScript
                       dataflow library can overflow the default 512 KB JVM
                       stack.  64 MB gives ample headroom without meaningfully
                       reducing heap space.
  -J=-XX:+UseG1GC      G1GC handles large heaps (10 GB) with shorter pause
                       times than the default collector, which matters for
                       long-running batch analysis.

Batch strategy (run_codeql_queries_batch):
  Previously the batch function ran `database analyze` TWICE — once for SARIF
  and once for CSV — which re-evaluated every query from scratch both times.
  Now it uses the split two-step approach:
    1. `database run-queries`   — evaluates all queries, stores BQRS in the DB
    2. `database interpret-results --format sarif-latest`  — reads stored BQRS
    3. `database interpret-results --format csv`           — reads stored BQRS
  Steps 2 and 3 are pure I/O (no re-evaluation), so the total wall-clock time
  is roughly halved compared to the previous approach.

  --no-rerun is NOT used here intentionally: the refinement loop regenerates
  queries between iterations, so we always want fresh evaluation.
"""

import os
import subprocess
import logging
import time
from typing import Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ── Performance configuration (all values read from environment variables) ────
#
# Set these in your shell or .env before running the pipeline.
# Recommended values for both target machines (16 GB RAM):
#
#   CODEQL_RAM=10240          # MB given to the CodeQL evaluator JVM heap
#   CODEQL_DISK_CACHE=4096    # MB for on-disk intermediate predicate cache
#   CODEQL_THREADS=0          # 0 = one thread per logical CPU core
#
# The JS extractor also reads CODEQL_RAM and CODEQL_THREADS automatically
# (via LGTM_TYPESCRIPT_RAM and LGTM_THREADS) — no extra config needed.
#
# Defaults are conservative (4 GB RAM, 2 GB cache, all cores) so the pipeline
# works out of the box on any machine without setting anything.

_RAM_MB        = int(os.environ.get("CODEQL_RAM",        "4096"))
_DISK_CACHE_MB = int(os.environ.get("CODEQL_DISK_CACHE", "2048"))
_THREADS       = int(os.environ.get("CODEQL_THREADS",    "0"))

# JVM flags injected via the -J= launcher prefix understood by the CodeQL shell
# wrapper.  Xss64m prevents StackOverflow in deep JS taint-tracking recursion.
# G1GC gives shorter GC pauses under large heaps (>4 GB).
# Both are always safe to include regardless of machine.
_JVM_FLAGS = [
    "-J=-Xss64m",
    "-J=-XX:+UseG1GC",
]

def _perf_flags() -> list:
    """Return the standard performance flags shared by all CodeQL subcommands."""
    return [
        f"--threads={_THREADS}",
        f"--ram={_RAM_MB}",
        f"--max-disk-cache={_DISK_CACHE_MB}",
    ]

# ── run_codeql_query_tables ───────────────────────────────────────────────────

def run_codeql_query_tables(database_path: str, query_path: str, output_path: str) -> Tuple[bool, Optional[str], float]:
    """
    Run a @kind table CodeQL query and decode the result to CSV.

    Used for:
      - getPackageMethods.ql  (Stage 3 — dependency method extraction)
      - extractCallGraph.ql   (Stage 8 — call graph extraction)
      - Sanitizer predicate validation queries (Stage 6 refinement loop)
      - Sink/flow predicate validation queries (Stage 8 refinement loop)

    Args:
        database_path: Path to the CodeQL database.
        query_path:    Path to the .ql query file.
        output_path:   Base output path (extensions .bqrs and .csv are appended).

    Returns:
        (success, error_message | None, elapsed_seconds)
    """
    start_time = time.time()

    if not os.path.exists(database_path):
        return False, f"Database path does not exist: {database_path}", 0.0
    if not os.path.exists(query_path):
        return False, f"Query path does not exist: {query_path}", 0.0

    bqrs_path = f"{output_path}.bqrs"
    csv_path  = f"{output_path}.csv"

    # Step 1: evaluate the query → BQRS
    command_run = [
        "codeql",
        *_JVM_FLAGS,
        "query", "run",
        f"--database={database_path}",
        f"--output={bqrs_path}",
        f"--threads={_THREADS}",
        f"--ram={_RAM_MB}",
        f"--max-disk-cache={_DISK_CACHE_MB}",
        "--no-metadata-verification",   # skip QLDoc metadata checks — saves ~100 ms per call
        query_path,
    ]

    # Step 2: decode BQRS → CSV (cheap I/O-only step, no re-evaluation)
    command_decode = [
        "codeql",
        *_JVM_FLAGS,
        "bqrs", "decode",
        f"--output={csv_path}",
        "--format=csv",
        "--no-titles",                  # omit header row — consistent with existing CSV readers
        bqrs_path,
    ]

    logger.info(f"[query run] {os.path.basename(query_path)} on {os.path.basename(database_path)}")

    try:
        subprocess.run(command_run, check=True, text=True, capture_output=True)
        logger.debug(f"BQRS written to {bqrs_path}")
    except subprocess.CalledProcessError as e:
        return False, f"query run failed (exit {e.returncode}): {e.stderr}", time.time() - start_time
    except Exception as e:
        return False, f"query run unexpected error: {e}", time.time() - start_time

    try:
        subprocess.run(command_decode, check=True, text=True, capture_output=True)
        logger.info(f"CSV written to {csv_path}")
        return True, None, time.time() - start_time
    except subprocess.CalledProcessError as e:
        return False, f"bqrs decode failed (exit {e.returncode}): {e.stderr}", time.time() - start_time
    except Exception as e:
        return False, f"bqrs decode unexpected error: {e}", time.time() - start_time


# ── run_codeql_path_problem ───────────────────────────────────────────────────

def run_codeql_path_problem(database_path: str, query_path: str, output_path: str) -> Tuple[bool, Optional[str], float]:
    """
    Run a @kind path-problem query and produce both SARIF and CSV output.

    Used during the iterative refinement loop (Stages 6 and 8) to validate
    that generated sink/flow predicates compile and execute correctly.

    Split two-step strategy:
      1. database run-queries  → stores BQRS inside the database directory
      2. database interpret-results --format sarif-latest → reads stored BQRS
      3. database interpret-results --format csv          → reads stored BQRS
    Steps 2 and 3 involve no re-evaluation — they only interpret the already-
    computed BQRS, so total cost ≈ one evaluation instead of two.

    Args:
        database_path: Path to the CodeQL database.
        query_path:    Path to the .ql query file.
        output_path:   Base output path (extensions .sarif and .csv are appended).

    Returns:
        (success, error_message | None, elapsed_seconds)
    """
    start_time = time.time()

    if not os.path.exists(database_path):
        return False, f"Database path does not exist: {database_path}", 0.0
    if not os.path.exists(query_path):
        return False, f"Query path does not exist: {query_path}", 0.0

    sarif_output = f"{output_path}.sarif"
    csv_output   = f"{output_path}.csv"

    # Step 1: evaluate — stores BQRS inside the database
    command_run = [
        "codeql",
        *_JVM_FLAGS,
        "database", "run-queries",
        f"--threads={_THREADS}",
        f"--ram={_RAM_MB}",
        f"--max-disk-cache={_DISK_CACHE_MB}",
        "--no-metadata-verification",
        database_path,
        query_path,
    ]

    # Step 2: interpret stored BQRS → SARIF (no re-evaluation)
    command_sarif = [
        "codeql",
        *_JVM_FLAGS,
        "database", "interpret-results",
        "--format=sarif-latest",
        f"--output={sarif_output}",
        "--no-print-diagnostics-summary",
        database_path,
        query_path,
    ]

    # Step 3: interpret stored BQRS → CSV (no re-evaluation)
    command_csv = [
        "codeql",
        *_JVM_FLAGS,
        "database", "interpret-results",
        "--format=csv",
        f"--output={csv_output}",
        "--no-print-diagnostics-summary",
        database_path,
        query_path,
    ]

    logger.info(f"[path-problem] {os.path.basename(query_path)} on {os.path.basename(database_path)}")

    try:
        subprocess.run(command_run, check=True, text=True, capture_output=True)
        logger.debug("run-queries complete, BQRS stored in database")
    except subprocess.CalledProcessError as e:
        return False, f"run-queries failed (exit {e.returncode}): {e.stderr}", time.time() - start_time
    except Exception as e:
        return False, f"run-queries unexpected error: {e}", time.time() - start_time

    # SARIF — primary output; failure here is fatal
    try:
        subprocess.run(command_sarif, check=True, text=True, capture_output=True)
        logger.info(f"SARIF written to {sarif_output}")
    except subprocess.CalledProcessError as e:
        return False, f"interpret-results (SARIF) failed (exit {e.returncode}): {e.stderr}", time.time() - start_time
    except Exception as e:
        return False, f"interpret-results (SARIF) unexpected error: {e}", time.time() - start_time

    # CSV — secondary output; failure is non-fatal (logged only)
    try:
        subprocess.run(command_csv, check=True, text=True, capture_output=True)
        logger.info(f"CSV written to {csv_output}")
    except Exception as e:
        logger.warning(f"Could not generate CSV output (non-fatal): {e}")

    return True, None, time.time() - start_time


# ── run_codeql_queries_batch ──────────────────────────────────────────────────

def run_codeql_queries_batch(database_path: str, queries_dir: str, output_dir: str, threads: int = 0) -> Tuple[bool, Optional[str], float]:
    """
    Run an entire directory of .ql queries in one parallel batch, producing
    both SARIF and CSV output.

    Used for Stage 9 (final batch execution of all generated + default queries).

    Split two-step strategy (same rationale as run_codeql_path_problem):
      1. database run-queries  — evaluates ALL queries in parallel, storing
                                 BQRS results inside the database directory.
                                 CodeQL's evaluator shares intermediate
                                 predicate results across queries in the same
                                 batch, so shared sub-computations (e.g. the
                                 call graph, dataflow graph) are computed once.
      2. database interpret-results --format sarif-latest
      3. database interpret-results --format csv
    Steps 2 and 3 are pure I/O — no re-evaluation.  Total wall-clock time is
    roughly half that of the previous approach (which ran `database analyze`
    twice, re-evaluating everything each time).

    The `threads` parameter is accepted for API compatibility but ignored —
    _THREADS (all cores) is always used for batch execution.

    Args:
        database_path: Path to the CodeQL database.
        queries_dir:   Directory containing .ql query files.
        output_dir:    Directory for batch_results.sarif and batch_results.csv.
        threads:       Ignored (kept for call-site compatibility).

    Returns:
        (success, error_message | None, elapsed_seconds)
    """
    start_time = time.time()

    if not os.path.exists(database_path):
        return False, f"Database path does not exist: {database_path}", 0.0
    if not os.path.exists(queries_dir):
        return False, f"Queries directory does not exist: {queries_dir}", 0.0

    query_files = [f for f in os.listdir(queries_dir) if f.endswith('.ql')]
    if not query_files:
        return False, f"No .ql files found in {queries_dir}", 0.0

    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"[batch] {len(query_files)} queries on {os.path.basename(database_path)} "
                f"(threads=all, ram={_RAM_MB} MB, disk-cache={_DISK_CACHE_MB} MB)")

    sarif_output = os.path.join(output_dir, "batch_results.sarif")
    csv_output   = os.path.join(output_dir, "batch_results.csv")

    # Step 1: evaluate all queries — shared intermediate predicates computed once
    command_run = [
        "codeql",
        *_JVM_FLAGS,
        "database", "run-queries",
        f"--threads={_THREADS}",
        f"--ram={_RAM_MB}",
        f"--max-disk-cache={_DISK_CACHE_MB}",
        "--no-metadata-verification",
        database_path,
        queries_dir,
    ]

    # Step 2: interpret → SARIF (reads stored BQRS, no re-evaluation)
    command_sarif = [
        "codeql",
        *_JVM_FLAGS,
        "database", "interpret-results",
        "--format=sarif-latest",
        f"--output={sarif_output}",
        "--no-print-diagnostics-summary",
        database_path,
        queries_dir,
    ]

    # Step 3: interpret → CSV (reads stored BQRS, no re-evaluation)
    command_csv = [
        "codeql",
        *_JVM_FLAGS,
        "database", "interpret-results",
        "--format=csv",
        f"--output={csv_output}",
        "--no-print-diagnostics-summary",
        database_path,
        queries_dir,
    ]

    # ── Step 1: evaluate ──────────────────────────────────────────────────────
    logger.info("Step 1/3: evaluating queries (run-queries)...")
    try:
        subprocess.run(command_run, check=True, text=True, capture_output=True)
        logger.info("run-queries complete")
    except subprocess.CalledProcessError as e:
        return False, f"run-queries failed (exit {e.returncode}): {e.stderr}", time.time() - start_time
    except Exception as e:
        return False, f"run-queries unexpected error: {e}", time.time() - start_time

    # ── Step 2: SARIF ─────────────────────────────────────────────────────────
    logger.info("Step 2/3: interpreting results → SARIF...")
    try:
        subprocess.run(command_sarif, check=True, text=True, capture_output=True)
        logger.info(f"SARIF written to {sarif_output}")
    except subprocess.CalledProcessError as e:
        # SARIF failure is fatal — it's the primary output
        return False, f"interpret-results (SARIF) failed (exit {e.returncode}): {e.stderr}", time.time() - start_time
    except Exception as e:
        return False, f"interpret-results (SARIF) unexpected error: {e}", time.time() - start_time

    # ── Step 3: CSV ───────────────────────────────────────────────────────────
    logger.info("Step 3/3: interpreting results → CSV...")
    try:
        subprocess.run(command_csv, check=True, text=True, capture_output=True)
        logger.info(f"CSV written to {csv_output}")
    except Exception as e:
        # CSV failure is non-fatal — SARIF is the canonical output
        logger.warning(f"Could not generate CSV output (non-fatal): {e}")

    elapsed = time.time() - start_time
    logger.info(f"[batch] completed in {elapsed:.1f}s")
    return True, None, elapsed
