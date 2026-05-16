"""
Vulnerable application evaluation pipeline.

Adapted version of evaluation_cves/specific_evaluator.py for evaluating the
system against intentionally vulnerable applications (DVNA, OWASP Juice Shop,
SecureGarden). Includes call graph extraction and CWE-specific call graph
filtering for project-aware query refinement.

Key differences from the CVE evaluator:
  - Works with pre-cloned applications (no CVE-based commit checkout)
  - Integrates call graph analysis for project-specific context
  - Supports batch query execution for efficiency

Note: This is a temporary adaptation pending full integration with the
CVE evaluator due to different project structure assumptions.
"""

import logging
import time
import os
import sys
import json
import shutil
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.general import extract_call_graph, format_call_graph_for_cwe
from utils.create_db import create_codeql_database
from utils.query_runner import run_codeql_query_tables, run_codeql_path_problem, run_codeql_queries_batch
from utils.methods_post_process import deduplicate_methods, methods_to_json, compare_with_advisories, classify_vulnerable_methods
from utils.query_generator import generate_codeql_package_classification, generate_conditional_sanitizer_library, cleanup_test_queries, refine_vulnerability_query
from utils.cwe_decider import cwes_to_check
from utils.LLM import set_current_project, get_llm_stats, get_all_project_stats, reset_llm_stats, InsufficientCreditsError

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# CodeQL tracking variables
_codeql_project_stats = defaultdict(lambda: {
    'db_creation_time': 0.0,
    'methods_extraction_time': 0.0,
    'refinement_query_count': 0,
    'refinement_query_time': 0.0,
    'query_count': 0,
    'total_query_time': 0.0
})

def track_codeql_db_creation(project_name, creation_time):
    """Track CodeQL database creation time for a project"""
    _codeql_project_stats[project_name]['db_creation_time'] = creation_time

def track_codeql_methods_extraction(project_name, extraction_time):
    """Track CodeQL methods extraction time for a project"""
    _codeql_project_stats[project_name]['methods_extraction_time'] = extraction_time

def track_codeql_refinement_query(project_name, query_time):
    """Track CodeQL refinement/validation query execution time for a project"""
    _codeql_project_stats[project_name]['refinement_query_count'] += 1
    _codeql_project_stats[project_name]['refinement_query_time'] += query_time

def track_codeql_query(project_name, query_time):
    """Track CodeQL query execution time for a project"""
    _codeql_project_stats[project_name]['query_count'] += 1
    _codeql_project_stats[project_name]['total_query_time'] += query_time

def get_codeql_stats(project_name):
    """Get CodeQL statistics for a project"""
    stats = _codeql_project_stats[project_name]
    total_codeql_time = (stats['db_creation_time'] + 
                         stats['methods_extraction_time'] + 
                         stats['refinement_query_time'] +
                         stats['total_query_time'])
    avg_query_time = stats['total_query_time'] / stats['query_count'] if stats['query_count'] > 0 else 0
    avg_refinement_time = stats['refinement_query_time'] / stats['refinement_query_count'] if stats['refinement_query_count'] > 0 else 0
    return {
        'db_creation_time': stats['db_creation_time'],
        'methods_extraction_time': stats['methods_extraction_time'],
        'refinement_query_count': stats['refinement_query_count'],
        'refinement_query_time': stats['refinement_query_time'],
        'average_refinement_time': avg_refinement_time,
        'query_count': stats['query_count'],
        'total_query_time': stats['total_query_time'],
        'average_query_time': avg_query_time,
        'total_codeql_time': total_codeql_time
    }

def get_all_codeql_stats():
    """Get CodeQL statistics for all projects"""
    return {project: get_codeql_stats(project) for project in _codeql_project_stats.keys()}

def get_total_codeql_stats():
    """Get total CodeQL statistics across all projects"""
    total_db_time = sum(s['db_creation_time'] for s in _codeql_project_stats.values())
    total_methods_time = sum(s['methods_extraction_time'] for s in _codeql_project_stats.values())
    total_refinement_count = sum(s['refinement_query_count'] for s in _codeql_project_stats.values())
    total_refinement_time = sum(s['refinement_query_time'] for s in _codeql_project_stats.values())
    total_query_count = sum(s['query_count'] for s in _codeql_project_stats.values())
    total_query_time = sum(s['total_query_time'] for s in _codeql_project_stats.values())
    total_codeql_time = total_db_time + total_methods_time + total_refinement_time + total_query_time
    avg_query_time = total_query_time / total_query_count if total_query_count > 0 else 0
    avg_refinement_time = total_refinement_time / total_refinement_count if total_refinement_count > 0 else 0
    
    return {
        'db_creation_time': total_db_time,
        'methods_extraction_time': total_methods_time,
        'refinement_query_count': total_refinement_count,
        'refinement_query_time': total_refinement_time,
        'average_refinement_time': avg_refinement_time,
        'query_count': total_query_count,
        'total_query_time': total_query_time,
        'average_query_time': avg_query_time,
        'total_codeql_time': total_codeql_time
    }

def problem_queries(cwes):
    registry_path = os.path.join(os.path.dirname(__file__), '..', 'codeql', 'registry.json')
    with open(registry_path, 'r') as f:
        registry = json.load(f)
    probs = []
    for cwe_id in cwes:
        if str(cwe_id) in registry: 
            prob = registry[str(cwe_id)]['problemQueries']
            for pr in prob:
                probs.append(pr)
    return probs


def append_project_stats(report_file_path, project_name, llm_stats, codeql_stats, project_start_time, project_end_time):
    """Append project statistics to the ongoing report file"""
    total_duration = project_end_time - project_start_time
    
    with open(report_file_path, 'a') as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"PROJECT: {project_name}\n")
        f.write(f"{'='*60}\n")
        f.write(f"Completion Time: {datetime.fromtimestamp(project_end_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Duration: {total_duration:.2f}s ({total_duration/60:.1f} min)\n")
        
        f.write(f"\nLLM Statistics:\n")
        f.write(f"  Duration: {llm_stats['total_request_time']:.2f}s ({llm_stats['total_request_time']/60:.1f} min)\n")
        f.write(f"  Requests: {llm_stats['request_count']}\n")
        f.write(f"  Average Request Time: {llm_stats['average_request_time']:.2f}s\n")
        f.write(f"  % of Total: {(llm_stats['total_request_time']/total_duration)*100:.1f}%\n")
        f.write(f"  Input Tokens: {llm_stats['total_input_tokens']:,}\n")
        f.write(f"  Output Tokens: {llm_stats['total_output_tokens']:,}\n")
        f.write(f"  Total Tokens: {llm_stats['total_tokens']:,}\n")
        
        f.write(f"\nCodeQL Statistics:\n")
        f.write(f"  DB Creation: {codeql_stats['db_creation_time']:.2f}s ({codeql_stats['db_creation_time']/60:.1f} min)\n")
        f.write(f"  Methods Extraction: {codeql_stats['methods_extraction_time']:.2f}s ({codeql_stats['methods_extraction_time']/60:.1f} min)\n")
        f.write(f"  Refinement/Validation Queries: {codeql_stats['refinement_query_time']:.2f}s ({codeql_stats['refinement_query_count']} queries)\n")
        f.write(f"  Final Analysis Queries: {codeql_stats['total_query_time']:.2f}s ({codeql_stats['query_count']} batch runs)\n")
        f.write(f"  Average Refinement Time: {codeql_stats['average_refinement_time']:.2f}s\n")
        f.write(f"  Total CodeQL Duration: {codeql_stats['total_codeql_time']:.2f}s ({codeql_stats['total_codeql_time']/60:.1f} min)\n")
        f.write(f"  % of Total: {(codeql_stats['total_codeql_time']/total_duration)*100:.1f}%\n")
        
        f.write(f"\nStatus: COMPLETED\n")
        f.flush()

def initialize_report_file(report_file_path, start_time):
    """Initialize the report file with header information"""
    with open(report_file_path, 'w') as f:
        f.write("LLM USAGE EVALUATION REPORT (BATCH QUERY EXECUTION)\n")
        f.write("=" * 60 + "\n")
        f.write(f"Started: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Report File: {os.path.basename(report_file_path)}\n")
        model_id = os.environ.get("ARIADNE_MODEL_ID", "unknown-model")
        embedding_model = os.environ.get("EMBEDDING_MODEL", "unknown-embedder")
        f.write("\nQuery Execution: Batch with threading (codeql database analyze --threads)\n")
        f.write(f"LLM Model: {model_id}\n")
        f.write(f"Embedding Model: {embedding_model}\n")
        f.write("\nThis file tracks progress in real-time. Each project is appended as completed.\n")
        f.write("=" * 60 + "\n")

def finalize_report(report_file_path, total_start_time, final_llm_stats, final_codeql_stats, 
                   all_project_llm_stats, all_project_codeql_stats, project_names, project_durations):
    """Add final summary to the report file"""
    total_end_time = time.time()
    total_execution_time = total_end_time - total_start_time
    
    with open(report_file_path, 'a') as f:
        f.write(f"\n\n{'='*60}\n")
        f.write("FINAL SUMMARY\n")
        f.write(f"{'='*60}\n")
        f.write(f"Completed: {datetime.fromtimestamp(total_end_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Execution Time: {total_execution_time:.2f}s ({total_execution_time/60:.1f} min, {total_execution_time/3600:.1f} hr)\n")
        f.write(f"Total LLM Time: {final_llm_stats['total_request_time']:.2f}s ({final_llm_stats['total_request_time']/60:.1f} min)\n")
        f.write(f"Total CodeQL Time: {final_codeql_stats['total_codeql_time']:.2f}s ({final_codeql_stats['total_codeql_time']/60:.1f} min)\n")
        f.write(f"  - DB Creation: {final_codeql_stats['db_creation_time']:.2f}s ({final_codeql_stats['db_creation_time']/60:.1f} min)\n")
        f.write(f"  - Methods Extraction: {final_codeql_stats['methods_extraction_time']:.2f}s ({final_codeql_stats['methods_extraction_time']/60:.1f} min)\n")
        f.write(f"  - Refinement/Validation: {final_codeql_stats['refinement_query_time']:.2f}s ({final_codeql_stats['refinement_query_count']} queries)\n")
        f.write(f"  - Final Analysis (Batch): {final_codeql_stats['total_query_time']:.2f}s\n")
        f.write(f"LLM % of Total: {(final_llm_stats['total_request_time']/total_execution_time)*100:.1f}%\n")
        f.write(f"CodeQL % of Total: {(final_codeql_stats['total_codeql_time']/total_execution_time)*100:.1f}%\n")
        f.write(f"Projects Processed: {len(project_names)}\n\n")
        
        f.write("GLOBAL LLM STATISTICS\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total LLM Requests: {final_llm_stats['request_count']}\n")
        f.write(f"Average Request Time: {final_llm_stats['average_request_time']:.2f}s\n")
        f.write(f"Total Input Tokens: {final_llm_stats['total_input_tokens']:,}\n")
        f.write(f"Total Output Tokens: {final_llm_stats['total_output_tokens']:,}\n")
        f.write(f"Total Tokens: {final_llm_stats['total_tokens']:,}\n\n")
        
        f.write("GLOBAL CODEQL STATISTICS\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total CodeQL Batch Runs: {final_codeql_stats['query_count']}\n\n")
        
        f.write("PROJECT COMPARISON\n")
        f.write("-" * 110 + "\n")
        f.write(f"{'Project':<20} {'Total(min)':<12} {'LLM(min)':<10} {'LLM%':<8} {'CodeQL(min)':<12} {'CodeQL%':<10} {'DB(min)':<10} {'Batches':<10}\n")
        f.write("-" * 110 + "\n")
        
        for project_name in project_names:
            llm_stats = all_project_llm_stats.get(project_name, {})
            codeql_stats = all_project_codeql_stats.get(project_name, {})
            project_total = project_durations.get(project_name, 0)
            
            llm_time = llm_stats.get('total_request_time', 0)
            codeql_time = codeql_stats.get('total_codeql_time', 0)
            db_time = codeql_stats.get('db_creation_time', 0)
            llm_percentage = (llm_time / project_total * 100) if project_total > 0 else 0
            codeql_percentage = (codeql_time / project_total * 100) if project_total > 0 else 0
            query_count = codeql_stats.get('query_count', 0)
            
            f.write(f"{project_name:<20} {project_total/60:<12.1f} {llm_time/60:<10.1f} {llm_percentage:<8.1f} {codeql_time/60:<12.1f} {codeql_percentage:<10.1f} {db_time/60:<10.1f} {query_count:<10}\n")
        
        f.write("-" * 110 + "\n")
        llm_percentage = (final_llm_stats['total_request_time'] / total_execution_time * 100) if total_execution_time > 0 else 0
        codeql_percentage = (final_codeql_stats['total_codeql_time'] / total_execution_time * 100) if total_execution_time > 0 else 0
        f.write(f"{'TOTAL':<20} {total_execution_time/60:<12.1f} {final_llm_stats['total_request_time']/60:<10.1f} {llm_percentage:<8.1f} {final_codeql_stats['total_codeql_time']/60:<12.1f} {codeql_percentage:<10.1f} {final_codeql_stats['db_creation_time']/60:<10.1f} {final_codeql_stats['query_count']:<10}\n")
        
        f.write(f"\nTIME ANALYSIS\n")
        f.write("-" * 30 + "\n")
        if len(project_names) > 0:
            avg_total_per_project = total_execution_time / len(project_names)
            avg_llm_per_project = final_llm_stats['total_request_time'] / len(project_names)
            avg_codeql_per_project = final_codeql_stats['total_codeql_time'] / len(project_names)
            f.write(f"Average Total per Project: {avg_total_per_project/60:.1f} min\n")
            f.write(f"Average LLM per Project: {avg_llm_per_project/60:.1f} min\n")
            f.write(f"Average CodeQL per Project: {avg_codeql_per_project/60:.1f} min\n")
            f.write(f"Average LLM Requests per Project: {final_llm_stats['request_count'] / len(project_names):.1f}\n")
        
        f.write(f"\n{'='*60}\n")
        f.write("EVALUATION COMPLETED SUCCESSFULLY\n")
        f.write(f"{'='*60}\n")

def _checkpoint_exists(path):
    """Return True if a checkpoint file/directory exists and is non-empty."""
    if os.path.isdir(path):
        return any(os.scandir(path))
    return os.path.exists(path) and os.path.getsize(path) > 0


def process_single_project(project_name, codebases_folder, project_root, report_file_path, codebase_subfolder=None):
    """Process a single project - designed to run in parallel with other projects"""
    project_start_time = time.time()

    # set current project for llm tracking
    set_current_project(project_name)
    reset_llm_stats(project_name)

    # Model name used for query filename suffix — sanitize '/' for filesystem safety
    model_name = os.environ.get("ARIADNE_MODEL_ID", "unknown-model").replace("/", "-")

    project_path = os.path.join(codebases_folder, project_name)
    logger.info(f"Processing project: {project_name}")

    try:
        output_dir = os.path.join(project_root, "output", project_name)
        os.makedirs(output_dir, exist_ok=True)

        database_path = os.path.join(project_root, "databases", project_name)
        results_path = os.path.join(output_dir, "methods")
        classified_path = f"{results_path}_vulnerable_classified.json"
        project_specific_dir = os.path.join(project_root, "codeql", "project_specific", project_name)
        os.makedirs(project_specific_dir, exist_ok=True)
        vmclass_qll = os.path.join(project_specific_dir, "VulnerableMethodsClassification.qll")
        sanitizers_qll = os.path.join(project_specific_dir, "ConditionalSanitizers.qll")

        # ── CHECKPOINT: methods + classification ──────────────────────────
        if _checkpoint_exists(classified_path):
            logger.info(f"[RESUME] Skipping methods extraction and classification — checkpoint found: {classified_path}")
            with open(classified_path, 'r') as f:
                classified_methods = json.load(f)
            # DB may not exist if we're resuming on a fresh machine; rebuild only if needed
            if not _checkpoint_exists(database_path):
                success, message, db_time = create_codeql_database(project_path, response='n')
                if not success:
                    logger.error(f"Error creating CodeQL database for {project_name}: {message}")
                    return (project_name, False, 0, f"Database creation failed: {message}")
                track_codeql_db_creation(project_name, db_time)
                logger.info(f"Database created in {db_time:.1f}s")
        else:
            # create codeql database
            success, message, db_time = create_codeql_database(project_path, response='n')
            if not success:
                logger.error(f"Error creating CodeQL database for {project_name}: {message}")
                return (project_name, False, 0, f"Database creation failed: {message}")
            track_codeql_db_creation(project_name, db_time)
            logger.info(f"Database created in {db_time:.1f}s")

            ## EXTRACT METHODS FROM DEPENDENCIES ##
            query_path = os.path.join(project_root, "codeql", "getPackageMethods.ql")

            # run the CodeQL query to extract methods from dependencies
            success, error, extraction_time = run_codeql_query_tables(database_path, query_path, results_path)
            if not success:
                logger.error(f"Error running methods extraction query: {error}")
                return (project_name, False, 0, f"Methods extraction failed: {error}")
            track_codeql_methods_extraction(project_name, extraction_time)
            logger.info(f"Methods extraction completed in {extraction_time:.1f}s. Results saved to {results_path}.csv")

            # deduplicate the df in case codeql returns duplicates
            processed_methods = deduplicate_methods(f"{results_path}.csv", f"{results_path}_processed.csv")

            # turn csv to json
            methods_json = methods_to_json(processed_methods, f"{results_path}.json")

            # check for vulnerable npm packages
            vulnerable_packages = compare_with_advisories(methods_json, output_path=f"{results_path}_vulnerable.json")

            # classify vulnerable methods
            classified_methods = classify_vulnerable_methods(vulnerable_packages, classified_path)

        # ── CHECKPOINT: .qll library generation ───────────────────────────
        if _checkpoint_exists(vmclass_qll) and _checkpoint_exists(sanitizers_qll):
            logger.info(f"[RESUME] Skipping .qll library generation — checkpoints found")
        else:
            # generate codeql library for package classifications (source, sinks, propagators)
            generate_codeql_package_classification(classified_methods, vmclass_qll)

            # conditional sanitizers
            generate_conditional_sanitizer_library(classified_methods, sanitizers_qll, validation_db=project_name)

        cleanup_test_queries(project_specific_dir)

        # decide CWEs to check
        cwes = cwes_to_check(project_name, extra_folder=codebase_subfolder)
        #cwes_filtered = [cwe for cwe in cwes if cwe >= 330] # temp: only check CWEs >= x if something goes wrong during evaluation
        logger.info(f"CWEs to check for {project_name}: {cwes}")

        # Extract call graph ONCE for this project
        logger.info(f"Extracting call graph for {project_name}")
        call_graph_df = extract_call_graph(database_path, project_name, include_frontend=True)

        if call_graph_df is None:
            logger.warning(f"Failed to extract call graph for {project_name}, proceeding without it")

        # refine vulnerability query for each CWE; on failure skip only the current CWE
        failed_cwes = []
        _failed_cwes_lock = threading.Lock()
        _credit_exhausted = threading.Event()

        def _refine_one_cwe(cwe_id):
            # ── CHECKPOINT: per-CWE final query ───────────────────────────
            final_query_path = os.path.join(
                project_specific_dir,
                f"cwe_{cwe_id}_vulnerability_final_{model_name}.ql"
            )
            if _checkpoint_exists(final_query_path):
                logger.info(f"[RESUME] Skipping CWE-{cwe_id} — final query already exists")
                return

            try:
                formatted_call_graph = None
                if call_graph_df is not None:
                    formatted_call_graph = format_call_graph_for_cwe(call_graph_df, cwe_id, project_name)
                refine_vulnerability_query(cwe_id, project_name, general=False, extra_folder=codebase_subfolder,
                               call_graph=formatted_call_graph, track_query_fn=track_codeql_refinement_query)
            except InsufficientCreditsError:
                _credit_exhausted.set()
                raise  # propagate so the future carries the exception
            except Exception as e:
                logger.warning("Failed to refine query for CWE %s in %s: %s. Skipping this CWE.", cwe_id, project_name, str(e))
                with _failed_cwes_lock:
                    failed_cwes.append((cwe_id, str(e)))

        max_workers = min(len(cwes), int(os.environ.get("CWE_WORKERS", "8")))
        logger.info(f"Processing {len(cwes)} CWEs with {max_workers} parallel workers")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_refine_one_cwe, cwe_id): cwe_id for cwe_id in cwes}
            for future in as_completed(futures):
                try:
                    future.result()
                except InsufficientCreditsError:
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise  # propagate immediately — do not swallow into failed_cwes

        # If any CWE refinements failed, append details to the project report so it's recorded
        if failed_cwes:
            with open(report_file_path, 'a') as f:
                f.write("\n" + ("-"*60) + "\n")
                f.write(f"PROJECT: {project_name} - CWE REFINEMENT ISSUES\n")
                f.write(("-"*60) + "\n")
                f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("The following CWEs failed during the refine_vulnerability_query step and were skipped:\n")
                for cwe, err in failed_cwes:
                    # Keep the error message short to avoid huge report entries
                    snippet = (err[:1000] + '...') if len(err) > 1000 else err
                    f.write(f"- {cwe}: {snippet}\n")
                f.flush()

        # BATCH QUERY EXECUTION
        # ── CHECKPOINT: batch results ──────────────────────────────────────
        batch_output_dir = os.path.join(project_root, "output", f"{project_name}_callgraphs1", project_name)
        batch_results_path = os.path.join(batch_output_dir, "batch_results.csv")
        if _checkpoint_exists(batch_results_path):
            logger.info(f"[RESUME] Skipping batch execution — results already exist: {batch_results_path}")
            track_codeql_query(project_name, 0.0)
        else:
            logger.info(f"Preparing batch queries for {project_name}")
        batch_queries_dir = os.path.join(project_specific_dir, "batch_queries")
        if not _checkpoint_exists(batch_results_path):
            os.makedirs(batch_queries_dir, exist_ok=True)

            # Copy final queries to batch folder
            final_query_suffix = f"final_{model_name}.ql"
            if os.path.exists(project_specific_dir):
                final_queries = [f for f in os.listdir(project_specific_dir)
                               if f.endswith(final_query_suffix)]

                for query_file in final_queries:
                    src = os.path.join(project_specific_dir, query_file)
                    dst = os.path.join(batch_queries_dir, query_file)
                    shutil.copy(src, dst)

                # Copy library files
                for lib_file in ["ConditionalSanitizers.qll", "VulnerableMethodsClassification.qll"]:
                    src = os.path.join(project_specific_dir, lib_file)
                    dst = os.path.join(batch_queries_dir, lib_file)
                    if os.path.exists(src):
                        shutil.copy(src, dst)

                # Copy problem queries
                prob_queries_list = problem_queries(cwes)
                for prob in prob_queries_list:
                    src = os.path.join(project_root, prob)
                    dst = os.path.join(batch_queries_dir, os.path.basename(prob))
                    if os.path.exists(src):
                        shutil.copy(src, dst)

                logger.info(f"Copied {len(final_queries)} final queries and {len(prob_queries_list)} problem queries to batch folder")

            # Run batch queries with threading
            logger.info(f"Running batch queries for {project_name} with parallel execution (--threads=0)")
            os.makedirs(batch_output_dir, exist_ok=True)

            success, error, batch_time = run_codeql_queries_batch(database_path, batch_queries_dir, batch_output_dir, threads=0)
            track_codeql_query(project_name, batch_time)

            if not success:
                logger.error(f"Batch query execution failed for {project_name}: {error}")
            else:
                logger.info(f"Batch query execution completed in {batch_time:.1f}s")

        # NOW the project is truly completed
        project_end_time = time.time()
        total_duration = project_end_time - project_start_time
        
        project_stats = get_llm_stats(project_name)
        codeql_stats = get_codeql_stats(project_name)
        
        # Enhanced console logging
        logger.info(f"Completed {project_name}:")
        logger.info(f"  - Total time: {total_duration:.1f}s ({total_duration/60:.1f} min)")
        logger.info(f"  - LLM time: {project_stats['total_request_time']:.1f}s ({project_stats['total_request_time']/60:.1f} min)")
        logger.info(f"  - CodeQL time: {codeql_stats['total_codeql_time']:.1f}s ({codeql_stats['total_codeql_time']/60:.1f} min)")
        logger.info(f"    - DB creation: {codeql_stats['db_creation_time']:.1f}s")
        logger.info(f"    - Methods extraction: {codeql_stats['methods_extraction_time']:.1f}s")
        logger.info(f"    - Batch queries: {codeql_stats['total_query_time']:.1f}s ({codeql_stats['query_count']} batch runs)")
        logger.info(f"  - LLM %: {(project_stats['total_request_time']/total_duration)*100:.1f}%")
        logger.info(f"  - CodeQL %: {(codeql_stats['total_codeql_time']/total_duration)*100:.1f}%")
        
        # Append to report file
        append_project_stats(report_file_path, project_name, project_stats, codeql_stats, project_start_time, project_end_time)
        
        return (project_name, True, total_duration, None, project_stats, codeql_stats)
        
    except InsufficientCreditsError as e:
        # Freeze cleanly — write checkpoint notice and exit with code 2
        project_end_time = time.time()
        total_duration = project_end_time - project_start_time
        logger.error(f"[FROZEN] Experiment paused — insufficient credits after {total_duration:.1f}s")
        logger.error(f"[FROZEN] {e}")
        with open(report_file_path, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"PROJECT: {project_name}\n")
            f.write(f"{'='*60}\n")
            f.write(f"Status: FROZEN (insufficient credits)\n")
            f.write(f"Error: {str(e)}\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration before freeze: {total_duration:.2f} seconds\n")
            f.write(f"\nTo resume: recharge credits, then re-run the exact same command.\n")
            f.write(f"The pipeline will skip all completed phases and CWEs automatically.\n")
            f.flush()
        logger.error("[FROZEN] To resume:")
        logger.error("[FROZEN]   1. Recharge credits at https://ariadne.issel.ee.auth.gr")
        logger.error("[FROZEN]   2. Re-run the exact same command")
        logger.error("[FROZEN] The pipeline will skip all completed phases and CWEs automatically.")
        sys.exit(2)

    except Exception as e:
        # Log error
        project_end_time = time.time()
        total_duration = project_end_time - project_start_time

        logger.error(f"Error processing {project_name} after {total_duration:.1f}s: {str(e)}")
        with open(report_file_path, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"PROJECT: {project_name}\n")
            f.write(f"{'='*60}\n")
            f.write(f"Status: FAILED\n")
            f.write(f"Error: {str(e)}\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration before failure: {total_duration:.2f} seconds\n")
            f.flush()

        try:
            project_stats = get_llm_stats(project_name)
            codeql_stats = get_codeql_stats(project_name)
        except:
            project_stats = {}
            codeql_stats = {}

        return (project_name, False, total_duration, str(e), project_stats, codeql_stats)

def main():
    start_time = time.time()

    # reset llm stats
    reset_llm_stats()
    logger.info("LLM tracking initialized")

    # Create reports directory and initialize report file
    project_root = os.path.join(os.path.dirname(__file__), "..")
    reports_dir = os.path.join(project_root, "output", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file_path = os.path.join(reports_dir, f"llm_evaluation_batch_{timestamp}.txt")
    
    initialize_report_file(report_file_path, start_time)
    logger.info(f"Progress report initialized: {report_file_path}")

    model_id = os.environ.get("ARIADNE_MODEL_ID", "unknown-model")
    embedding_model = os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    logger.info(f"=== LLM: {model_id} | Embedder: {embedding_model} ===")


    project_names = [os.environ.get("PROJECT_NAME", "dvna")]
    # CODEBASE_SUBFOLDER: optional subdirectory inside codebases/ that contains the
    # project.  Use this when the source lives at codebases/<subfolder>/<project_name>
    # rather than directly at codebases/<project_name>.
    # Example: sgarden backend → PROJECT_NAME=backend CODEBASE_SUBFOLDER=sgarden
    codebase_subfolder = os.environ.get("CODEBASE_SUBFOLDER", "").strip()
    if codebase_subfolder:
        codebases_folder = os.path.join(project_root, "codebases", codebase_subfolder)
    else:
        codebases_folder = os.path.join(project_root, "codebases")

    completed_projects = []
    project_durations = {}  # Track individual project durations

    # Determine number of workers for project-level parallelization
    num_workers = min(len(project_names), multiprocessing.cpu_count())
    
    if len(project_names) == 1:
        # Single project - no multiprocessing overhead
        logger.info("Processing single project")
        result = process_single_project(project_names[0], codebases_folder, project_root, report_file_path, codebase_subfolder=codebase_subfolder)
        project_name, success, duration, error, proj_stats, cql_stats = result
        if success:
            completed_projects.append(project_name)
        project_durations[project_name] = duration
    else:
        # Multiple projects - use multiprocessing for parallel execution
        logger.info(f"Processing {len(project_names)} projects in parallel with {num_workers} workers")
        
        # Use partial to fix the common arguments
        process_func = partial(process_single_project,
                              codebases_folder=codebases_folder,
                              project_root=project_root,
                              report_file_path=report_file_path,
                              codebase_subfolder=codebase_subfolder)
        
        with multiprocessing.Pool(processes=num_workers) as pool:
            results = pool.map(process_func, project_names)
        
        # Process results
        for project_name, success, duration, error, proj_stats, cql_stats in results:
            if success:
                completed_projects.append(project_name)
            project_durations[project_name] = duration

        if proj_stats and isinstance(proj_stats, dict):
                # Merge LLM stats into main process globals
                from utils.LLM import _project_stats as llm_project_stats
                from utils.LLM import _global_stats as llm_global_stats
                
                llm_project_stats[project_name] = proj_stats
                
                # Aggregate into global stats
                llm_global_stats['request_count'] += proj_stats.get('request_count', 0)
                llm_global_stats['total_request_time'] += proj_stats.get('total_request_time', 0)
                llm_global_stats['total_input_tokens'] += proj_stats.get('total_input_tokens', 0)
                llm_global_stats['total_output_tokens'] += proj_stats.get('total_output_tokens', 0)
            
        if cql_stats and isinstance(cql_stats, dict):
            # Merge CodeQL stats into main process globals
            _codeql_project_stats[project_name] = {
                'db_creation_time': cql_stats.get('db_creation_time', 0),
                'methods_extraction_time': cql_stats.get('methods_extraction_time', 0),
                'refinement_query_count': cql_stats.get('refinement_query_count', 0),
                'refinement_query_time': cql_stats.get('refinement_query_time', 0),
                'query_count': cql_stats.get('query_count', 0),
                'total_query_time': cql_stats.get('total_query_time', 0)
            }
            
        logger.info(f"All {len(project_names)} projects completed")

    # Final statistics
    end_time = time.time()
    total_execution_time = end_time - start_time
    final_llm_stats = get_llm_stats()
    final_codeql_stats = get_total_codeql_stats()
    all_project_llm_stats = get_all_project_stats()
    all_project_codeql_stats = get_all_codeql_stats()
    
    finalize_report(report_file_path, start_time, final_llm_stats, final_codeql_stats,
                all_project_llm_stats, all_project_codeql_stats, completed_projects, project_durations)
    
    # Enhanced console summary
    logger.info("="*60)
    logger.info("EVALUATION COMPLETED (BATCH QUERY EXECUTION)")
    logger.info("="*60)
    logger.info(f"Total execution time: {total_execution_time:.1f}s ({total_execution_time/60:.1f} min, {total_execution_time/3600:.1f} hr)")
    logger.info(f"Total LLM time: {final_llm_stats['total_request_time']:.1f}s ({final_llm_stats['total_request_time']/60:.1f} min)")
    logger.info(f"LLM % of total: {(final_llm_stats['total_request_time']/total_execution_time)*100:.1f}%")
    logger.info(f"Projects completed: {len(completed_projects)}/{len(project_names)}")
    logger.info(f"Total LLM requests: {final_llm_stats['request_count']}")
    logger.info(f"Total CodeQL time: {final_codeql_stats['total_codeql_time']:.1f}s ({final_codeql_stats['total_codeql_time']/60:.1f} min)")
    logger.info(f"  - DB creation: {final_codeql_stats['db_creation_time']:.1f}s ({final_codeql_stats['db_creation_time']/60:.1f} min)")
    logger.info(f"  - Methods extraction: {final_codeql_stats['methods_extraction_time']:.1f}s ({final_codeql_stats['methods_extraction_time']/60:.1f} min)")
    logger.info(f"  - Batch queries: {final_codeql_stats['total_query_time']:.1f}s")
    logger.info(f"CodeQL % of total: {(final_codeql_stats['total_codeql_time']/total_execution_time)*100:.1f}%")
    logger.info(f"Avg time per project: {total_execution_time/len(completed_projects)/60:.1f} min" if completed_projects else "N/A")
    logger.info(f"Full report saved to: {report_file_path}")
    logger.info("="*60)

if __name__ == "__main__":
    main()