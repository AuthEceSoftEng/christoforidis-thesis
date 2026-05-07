"""
CVE-based evaluation pipeline with detailed performance tracking.

Runs the full vulnerability detection pipeline against real-world CVEs:
  1. Clone repositories at their pre-patch (vulnerable) commits
  2. Create CodeQL databases from the source code
  3. Extract npm package methods and match against GitHub Security Advisories
  4. Classify methods using LLM and generate CodeQL libraries
  5. Determine applicable CWEs and generate/refine vulnerability queries
  6. Run final queries and collect results

Tracks detailed timing statistics for both LLM and CodeQL operations
per project, enabling performance analysis of each pipeline stage.
Outputs progress reports to output/reports/.
"""

import logging
import time
import os
import sys
import json
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.scraper import clone_vulnerable_repos
from utils.create_db import create_codeql_database
from utils.query_runner import run_codeql_query_tables, run_codeql_path_problem
from utils.methods_post_process import deduplicate_methods, methods_to_json, compare_with_advisories, classify_vulnerable_methods
from utils.query_generator import generate_codeql_package_classification, generate_conditional_sanitizer_library, cleanup_test_queries, refine_vulnerability_query
from utils.cwe_decider import cwes_to_check
from utils.LLM import set_current_project, get_llm_stats, get_all_project_stats, reset_llm_stats

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
    logger.debug(f"Loading registry from {registry_path}")
    try:
        with open(registry_path, 'r') as f:
            registry = json.load(f)
    except FileNotFoundError:
        logger.error(f"Registry file not found: {registry_path}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse registry JSON: {e}")
        return []
    probs = []
    for cwe_id in cwes:
        if str(cwe_id) in registry:
            prob = registry[str(cwe_id)].get('problemQueries', [])
            if not prob:
                logger.warning(f"CWE {cwe_id} found in registry but has no problemQueries")
            for pr in prob:
                probs.append(pr)
        else:
            logger.debug(f"CWE {cwe_id} not found in registry — no problem queries for it")
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
        f.write(f"  Final Analysis Queries: {codeql_stats['total_query_time']:.2f}s ({codeql_stats['query_count']} queries)\n")
        f.write(f"  Average Refinement Time: {codeql_stats['average_refinement_time']:.2f}s\n")
        f.write(f"  Average Analysis Time: {codeql_stats['average_query_time']:.2f}s\n")
        f.write(f"  Total CodeQL Duration: {codeql_stats['total_codeql_time']:.2f}s ({codeql_stats['total_codeql_time']/60:.1f} min)\n")
        f.write(f"  % of Total: {(codeql_stats['total_codeql_time']/total_duration)*100:.1f}%\n")
        
        f.write(f"\nStatus: COMPLETED\n")
        f.flush()

def initialize_report_file(report_file_path, start_time):
    """Initialize the report file with header information"""
    with open(report_file_path, 'w') as f:
        f.write("LLM USAGE EVALUATION REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Started: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Report File: {os.path.basename(report_file_path)}\n")
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
        f.write(f"  - Final Analysis: {final_codeql_stats['total_query_time']:.2f}s ({final_codeql_stats['query_count']} queries)\n")
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
        f.write(f"Total CodeQL Queries: {final_codeql_stats['query_count']}\n")
        f.write(f"Average Query Time: {final_codeql_stats['average_query_time']:.2f}s\n\n")
        
        f.write("PROJECT COMPARISON\n")
        f.write("-" * 110 + "\n")
        f.write(f"{'Project':<20} {'Total(min)':<12} {'LLM(min)':<10} {'LLM%':<8} {'CodeQL(min)':<12} {'CodeQL%':<10} {'DB(min)':<10} {'Queries':<10}\n")
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
            f.write(f"Average CodeQL Queries per Project: {final_codeql_stats['query_count'] / len(project_names):.1f}\n")
        
        f.write(f"\n{'='*60}\n")
        f.write("EVALUATION COMPLETED SUCCESSFULLY\n")
        f.write(f"{'='*60}\n")

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
    report_file_path = os.path.join(reports_dir, f"llm_evaluation_progress_{timestamp}.txt")
    
    initialize_report_file(report_file_path, start_time)
    logger.info(f"Progress report initialized: {report_file_path}")

    cves_folder = os.path.join(os.path.dirname(__file__), "mini_evaluation")
    codebases_folder = os.path.join(os.path.dirname(__file__), "..", "codebases", "mini_cloned_repos")

    clone_vulnerable_repos(cves_folder, codebases_folder)

    project_names = [name for name in os.listdir(codebases_folder) if os.path.isdir(os.path.join(codebases_folder, name))]
    # project_names = ["swagger-u-c8ad396"] # TEMPORARY
    logger.info(f"Cloned repositories for evaluation: {project_names}")

    completed_projects = []
    project_durations = {}  # Track individual project durations

    for project_name in project_names:

        project_start_time = time.time()
        
        # set current project for llm tracking
        set_current_project(project_name)
        reset_llm_stats(project_name)

        project_path = os.path.join(codebases_folder, project_name)
        logger.info(f"Processing project: {project_name}")
        
        try:
            output_dir = os.path.join(project_root, "output", project_name)
            os.makedirs(output_dir, exist_ok=True)

            # create codeql database
            success, message, db_time = create_codeql_database(project_path, response='n')
            if not success:
                logger.error(f"Error creating CodeQL database for {project_name}: {message}")
                continue
            track_codeql_db_creation(project_name, db_time)
            logger.info(f"Database created in {db_time:.1f}s")

            database_path = os.path.join(project_root, "databases", project_name)

            ## EXTRACT METHODS FROM DEPENDENCIES ##
            query_path = os.path.join(project_root, "codeql", "getPackageMethods.ql")
            results_path = os.path.join(output_dir, "methods")

            # run the CodeQL query to extract methods from dependencies
            logger.info(f"Running methods extraction query: {query_path} → {results_path}")
            success, error, extraction_time = run_codeql_query_tables(database_path, query_path, results_path)
            if not success:
                logger.error(f"Methods extraction query failed for {project_name}: {error}")
                continue  # skip project, not the entire run
            track_codeql_methods_extraction(project_name, extraction_time)
            logger.info(f"Methods extraction completed in {extraction_time:.1f}s. Results saved to {results_path}.csv")

            # deduplicate the df in case codeql returns duplicates
            logger.debug(f"Deduplicating methods from {results_path}.csv")
            processed_methods = deduplicate_methods(f"{results_path}.csv", f"{results_path}_processed.csv")
            if processed_methods is None or (hasattr(processed_methods, '__len__') and len(processed_methods) == 0):
                logger.warning(f"No methods after deduplication for {project_name} — advisory matching will be empty")

            # turn csv to json
            logger.debug(f"Converting methods to JSON: {results_path}.json")
            methods_json = methods_to_json(processed_methods, f"{results_path}.json")
            if not methods_json:
                logger.warning(f"methods_to_json returned empty result for {project_name}")

            # check for vulnerable npm packages
            logger.info(f"Comparing methods against advisories for {project_name}")
            vulnerable_packages = compare_with_advisories(methods_json, output_path=f"{results_path}_vulnerable.json")
            logger.info(f"Advisory match: {len(vulnerable_packages) if vulnerable_packages else 0} vulnerable package(s) found")

            # classify vulnerable methods
            logger.info(f"Classifying {len(vulnerable_packages) if vulnerable_packages else 0} vulnerable method(s) for {project_name}")
            classified_methods = classify_vulnerable_methods(vulnerable_packages, f"{results_path}_vulnerable_classified.json")
            if not classified_methods:
                logger.warning(f"classify_vulnerable_methods returned empty result for {project_name} — generated libraries will be stubs")

            # generate codeql library for package classifications (source, sinks, propagators)
            project_specific_dir = os.path.join(project_root, "codeql", "project_specific", project_name)
            os.makedirs(project_specific_dir, exist_ok=True)
            qll_path = os.path.join(project_specific_dir, "VulnerableMethodsClassification.qll")
            logger.debug(f"Generating VulnerableMethodsClassification.qll → {qll_path}")
            generate_codeql_package_classification(classified_methods, qll_path)

            # conditional sanitizers
            qll_path = os.path.join(project_specific_dir, "ConditionalSanitizers.qll")
            logger.debug(f"Generating ConditionalSanitizers.qll → {qll_path}")
            generate_conditional_sanitizer_library(classified_methods, qll_path, validation_db=project_name)

            cleanup_test_queries(project_specific_dir)

            # decide CWEs to check
            cwes = cwes_to_check(project_name, extra_folder="mini_cloned_repos")
            if not cwes:
                logger.warning(f"cwes_to_check returned no CWEs for {project_name} — query refinement and final queries will be skipped")
            else:
                logger.info(f"CWEs to check for {project_name}: {cwes}")

            # refine vulnerability query for each CWE; on failure skip only the current CWE
            failed_cwes = []
            for cwe_id in cwes:
                try:
                    refine_vulnerability_query(cwe_id, project_name, general=False, extra_folder='mini_cloned_repos', track_query_fn=track_codeql_refinement_query)
                except Exception as e:
                    logger.warning("Failed to refine query for CWE %s in %s: %s. Skipping this CWE.", cwe_id, project_name, str(e))
                    failed_cwes.append((cwe_id, str(e)))
                    continue

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

            # Run final queries for this project (moved here from the separate loop)
            logger.info(f"Running final queries for {project_name}")
            if os.path.exists(project_specific_dir):
                queries = [f for f in os.listdir(project_specific_dir) if f.endswith('final_claude4compats.ql')]
                logger.info(f"Found {len(queries)} final path-problem query file(s) for {project_name}")

                for query in queries:
                    query_path = os.path.join(project_specific_dir, query)
                    output_path = os.path.join(project_root, "output", "mini_evaluation4", project_name, query)
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    logger.debug(f"Running final query: {query}")
                    success, error, query_time = run_codeql_path_problem(database_path, query_path, output_path)
                    if not success:
                        logger.error(f"Final query failed [{query}] for {project_name}: {error}")
                    track_codeql_query(project_name, query_time)

                prob_queries = problem_queries(cwes)
                logger.info(f"Found {len(prob_queries)} problem query file(s) for {project_name}")
                if len(prob_queries) > 0:
                    for query in prob_queries:
                        query_path = os.path.join(os.path.dirname(__file__), '..', query)
                        output_path = os.path.join(project_root, "output", "mini_evaluation4", project_name, "problems", query.replace('/', '_').replace('.ql', ''))
                        os.makedirs(os.path.dirname(output_path), exist_ok=True)
                        logger.debug(f"Running problem query: {query}")
                        success, error, query_time = run_codeql_path_problem(database_path, query_path, output_path)
                        if not success:
                            logger.error(f"Problem query failed [{query}] for {project_name}: {error}")
                        track_codeql_query(project_name, query_time)
            else:
                logger.warning(f"Project-specific dir not found, skipping final queries: {project_specific_dir}")

            # NOW the project is truly completed (after all queries including final ones)
            project_end_time = time.time()
            total_duration = project_end_time - project_start_time
            project_durations[project_name] = total_duration
            
            project_stats = get_llm_stats(project_name)
            codeql_stats = get_codeql_stats(project_name)
            
            # Enhanced console logging
            logger.info(f"Completed {project_name}:")
            logger.info(f"  - Total time: {total_duration:.1f}s ({total_duration/60:.1f} min)")
            logger.info(f"  - LLM time: {project_stats['total_request_time']:.1f}s ({project_stats['total_request_time']/60:.1f} min)")
            logger.info(f"  - CodeQL time: {codeql_stats['total_codeql_time']:.1f}s ({codeql_stats['total_codeql_time']/60:.1f} min)")
            logger.info(f"    - DB creation: {codeql_stats['db_creation_time']:.1f}s")
            logger.info(f"    - Methods extraction: {codeql_stats['methods_extraction_time']:.1f}s")
            logger.info(f"    - Other queries: {codeql_stats['total_query_time']:.1f}s ({codeql_stats['query_count']} queries)")
            logger.info(f"  - LLM %: {(project_stats['total_request_time']/total_duration)*100:.1f}%")
            logger.info(f"  - CodeQL %: {(codeql_stats['total_codeql_time']/total_duration)*100:.1f}%")
            
            # Append to report file immediately with complete timing
            append_project_stats(report_file_path, project_name, project_stats, codeql_stats, project_start_time, project_end_time)
            completed_projects.append(project_name)
            
            # Show running totals
            current_total_time = time.time() - start_time
            logger.info(f"Progress: {len(completed_projects)}/{len(project_names)} projects completed. Total runtime so far: {current_total_time/60:.1f} minutes")
            
        except Exception as e:
            # Log error and continue with next project
            project_end_time = time.time()
            total_duration = project_end_time - project_start_time
            project_durations[project_name] = total_duration
            
            logger.error(f"Error processing {project_name} after {total_duration:.1f}s: {str(e)}")
            with open(report_file_path, 'a') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"PROJECT: {project_name}\n")
                f.write(f"{'='*60}\n")
                f.write(f"Status: FAILED\n")
                f.write(f"Error: {str(e)}\n")
                f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration before failure: {total_duration:.2f} seconds\n")
            continue

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
    logger.info("EVALUATION COMPLETED")
    logger.info("="*60)
    logger.info(f"Total execution time: {total_execution_time:.1f}s ({total_execution_time/60:.1f} min, {total_execution_time/3600:.1f} hr)")
    logger.info(f"Total LLM time: {final_llm_stats['total_request_time']:.1f}s ({final_llm_stats['total_request_time']/60:.1f} min)")
    logger.info(f"LLM % of total: {(final_llm_stats['total_request_time']/total_execution_time)*100:.1f}%")
    logger.info(f"Projects completed: {len(completed_projects)}/{len(project_names)}")
    logger.info(f"Total LLM requests: {final_llm_stats['request_count']}")
    logger.info(f"Total CodeQL time: {final_codeql_stats['total_codeql_time']:.1f}s ({final_codeql_stats['total_codeql_time']/60:.1f} min)")
    logger.info(f"  - DB creation: {final_codeql_stats['db_creation_time']:.1f}s ({final_codeql_stats['db_creation_time']/60:.1f} min)")
    logger.info(f"  - Methods extraction: {final_codeql_stats['methods_extraction_time']:.1f}s ({final_codeql_stats['methods_extraction_time']/60:.1f} min)")
    logger.info(f"  - Other queries: {final_codeql_stats['total_query_time']:.1f}s")
    logger.info(f"CodeQL % of total: {(final_codeql_stats['total_codeql_time']/total_execution_time)*100:.1f}%")
    logger.info(f"Avg time per project: {total_execution_time/len(completed_projects)/60:.1f} min" if completed_projects else "N/A")
    logger.info(f"Full report saved to: {report_file_path}")
    logger.info("="*60)

if __name__ == "__main__":
    main()