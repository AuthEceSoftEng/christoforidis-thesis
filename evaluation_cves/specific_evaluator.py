import logging
import time
import os
import sys
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.scraper import clone_vulnerable_repos
from utils.create_db import create_codeql_database
from utils.query_runner import run_codeql_query_tables
from utils.methods_post_process import deduplicate_methods, methods_to_json, compare_with_advisories, classify_vulnerable_methods
from utils.query_generator import generate_codeql_package_classification, generate_conditional_sanitizer_library, cleanup_test_queries, refine_vulnerability_query
from utils.cwe_decider import cwes_to_check
from utils.query_runner import run_codeql_path_problem
from utils.LLM import set_current_project, get_llm_stats, get_all_project_stats, reset_llm_stats

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def append_project_stats(report_file_path, project_name, stats, project_start_time, project_end_time):
    """Append project statistics to the ongoing report file"""
    total_duration = project_end_time - project_start_time
    
    with open(report_file_path, 'a') as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"PROJECT: {project_name}\n")
        f.write(f"{'='*60}\n")
        f.write(f"Completion Time: {datetime.fromtimestamp(project_end_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Duration: {total_duration:.2f}s ({total_duration/60:.1f} min)\n")
        f.write(f"LLM Duration: {stats['total_request_time']:.2f}s ({stats['total_request_time']/60:.1f} min)\n")
        f.write(f"LLM Requests: {stats['request_count']}\n")
        f.write(f"Average Request Time: {stats['average_request_time']:.2f}s\n")
        f.write(f"LLM % of Total: {(stats['total_request_time']/total_duration)*100:.1f}%\n")
        f.write(f"Input Tokens: {stats['total_input_tokens']:,}\n")
        f.write(f"Output Tokens: {stats['total_output_tokens']:,}\n")
        f.write(f"Total Tokens: {stats['total_tokens']:,}\n")
        f.write(f"Status: COMPLETED\n")
        f.flush()  # Ensure data is written immediately

def initialize_report_file(report_file_path, start_time):
    """Initialize the report file with header information"""
    with open(report_file_path, 'w') as f:
        f.write("LLM USAGE EVALUATION REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Started: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Report File: {os.path.basename(report_file_path)}\n")
        f.write("\nThis file tracks progress in real-time. Each project is appended as completed.\n")
        f.write("=" * 60 + "\n")

def finalize_report(report_file_path, total_start_time, final_stats, all_project_stats, project_names, project_durations):
    """Add final summary to the report file"""
    total_end_time = time.time()
    total_execution_time = total_end_time - total_start_time
    
    with open(report_file_path, 'a') as f:
        f.write(f"\n\n{'='*60}\n")
        f.write("FINAL SUMMARY\n")
        f.write(f"{'='*60}\n")
        f.write(f"Completed: {datetime.fromtimestamp(total_end_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Execution Time: {total_execution_time:.2f}s ({total_execution_time/60:.1f} min, {total_execution_time/3600:.1f} hr)\n")
        f.write(f"Total LLM Time: {final_stats['total_request_time']:.2f}s ({final_stats['total_request_time']/60:.1f} min)\n")
        f.write(f"LLM % of Total: {(final_stats['total_request_time']/total_execution_time)*100:.1f}%\n")
        f.write(f"Projects Processed: {len(project_names)}\n\n")
        
        f.write("GLOBAL LLM STATISTICS\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total LLM Requests: {final_stats['request_count']}\n")
        f.write(f"Average Request Time: {final_stats['average_request_time']:.2f}s\n")
        f.write(f"Total Input Tokens: {final_stats['total_input_tokens']:,}\n")
        f.write(f"Total Output Tokens: {final_stats['total_output_tokens']:,}\n")
        f.write(f"Total Tokens: {final_stats['total_tokens']:,}\n\n")
        
        f.write("PROJECT COMPARISON\n")
        f.write("-" * 70 + "\n")
        f.write(f"{'Project':<20} {'Total(min)':<12} {'LLM(min)':<10} {'LLM%':<8} {'Requests':<10} {'Tokens':<12}\n")
        f.write("-" * 70 + "\n")
        
        for project_name, stats in all_project_stats.items():
            project_total = project_durations.get(project_name, 0)
            llm_percentage = (stats['total_request_time'] / project_total * 100) if project_total > 0 else 0
            f.write(f"{project_name:<20} {project_total/60:<12.1f} {stats['total_request_time']/60:<10.1f} {llm_percentage:<8.1f} {stats['request_count']:<10} {stats['total_tokens']:<12,}\n")
        
        f.write("-" * 70 + "\n")
        llm_percentage = (final_stats['total_request_time'] / total_execution_time * 100) if total_execution_time > 0 else 0
        f.write(f"{'TOTAL':<20} {total_execution_time/60:<12.1f} {final_stats['total_request_time']/60:<10.1f} {llm_percentage:<8.1f} {final_stats['request_count']:<10} {final_stats['total_tokens']:<12,}\n")
        
        f.write(f"\nTIME ANALYSIS\n")
        f.write("-" * 30 + "\n")
        if len(project_names) > 0:
            avg_total_per_project = total_execution_time / len(project_names)
            avg_llm_per_project = final_stats['total_request_time'] / len(project_names)
            f.write(f"Average Total per Project: {avg_total_per_project/60:.1f} min\n")
            f.write(f"Average LLM per Project: {avg_llm_per_project/60:.1f} min\n")
            f.write(f"Average Requests per Project: {final_stats['request_count'] / len(project_names):.1f}\n")
        
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
            success, message = create_codeql_database(project_path, response='n')
            if not success:
                logger.error(f"Error creating CodeQL database for {project_name}: {message}")
                continue

            database_path = os.path.join(project_root, "databases", project_name)

            ## EXTRACT METHODS FROM DEPENDENCIES ##
            query_path = os.path.join(project_root, "codeql", "getPackageMethods.ql")
            results_path = os.path.join(output_dir, "methods")

            # run the CodeQL query to extract methods from dependencies
            success, error = run_codeql_query_tables(database_path, query_path, results_path)
            if not success:
                logger.error(f"Error running methods extraction query: {error}")
                return
            logger.info(f"Methods extraction completed. Results saved to {results_path}.csv")
            
            # deduplicate the df in case codeql returns duplicates
            processed_methods = deduplicate_methods(f"{results_path}.csv", f"{results_path}_processed.csv")

            # turn csv to json
            methods_json = methods_to_json(processed_methods, f"{results_path}.json")

            # check for vulnerable npm packages
            vulnerable_packages = compare_with_advisories(methods_json, output_path=f"{results_path}_vulnerable.json")

            # classify vulnerable methods
            classified_methods = classify_vulnerable_methods(vulnerable_packages, f"{results_path}_vulnerable_classified.json")

            # generate codeql library for package classifications (source, sinks, propagators)
            project_specific_dir = os.path.join(project_root, "codeql", "project_specific", project_name)
            os.makedirs(project_specific_dir, exist_ok=True)
            qll_path = os.path.join(project_specific_dir, "VulnerableMethodsClassification.qll")
            generate_codeql_package_classification(classified_methods, qll_path)
            
            # conditional sanitizers
            qll_path = os.path.join(project_specific_dir, "ConditionalSanitizers.qll")
            generate_conditional_sanitizer_library(classified_methods, qll_path)

            cleanup_test_queries(project_specific_dir)

            # decide CWEs to check
            cwes = cwes_to_check(project_name, extra_folder="mini_cloned_repos")
            logger.info(f"CWEs to check for {project_name}: {cwes}")

            # refine vulnerability query for each CWE
            for cwe_id in cwes:
                refine_vulnerability_query(cwe_id, project_name, general=False, extra_folder='mini_cloned_repos')

            # Run final queries for this project (moved here from the separate loop)
            logger.info(f"Running final queries for {project_name}")
            if os.path.exists(project_specific_dir):
                queries = [f for f in os.listdir(project_specific_dir) if f.endswith('final_claude4new.ql')]

                for query in queries:
                    query_path = os.path.join(project_specific_dir, query)
                    output_path = os.path.join(project_root, "output", "mini_evaluation3", project_name, query)
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    run_codeql_path_problem(database_path, query_path, output_path)

            # NOW the project is truly completed (after all queries including final ones)
            project_end_time = time.time()
            total_duration = project_end_time - project_start_time
            project_durations[project_name] = total_duration
            
            project_stats = get_llm_stats(project_name)
            
            # Enhanced console logging
            logger.info(f"Completed {project_name}:")
            logger.info(f"  - Total time: {total_duration:.1f}s ({total_duration/60:.1f} min)")
            logger.info(f"  - LLM time: {project_stats['total_request_time']:.1f}s ({project_stats['total_request_time']/60:.1f} min)")
            logger.info(f"  - LLM requests: {project_stats['request_count']}")
            logger.info(f"  - LLM %: {(project_stats['total_request_time']/total_duration)*100:.1f}%")
            logger.info(f"  - Total tokens: {project_stats['total_tokens']:,}")
            
            # Append to report file immediately with complete timing
            append_project_stats(report_file_path, project_name, project_stats, project_start_time, project_end_time)
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
    final_stats = get_llm_stats()
    all_project_stats = get_all_project_stats()
    
    finalize_report(report_file_path, start_time, final_stats, all_project_stats, completed_projects, project_durations)
    
    # Enhanced console summary
    logger.info("="*60)
    logger.info("EVALUATION COMPLETED")
    logger.info("="*60)
    logger.info(f"Total execution time: {total_execution_time:.1f}s ({total_execution_time/60:.1f} min, {total_execution_time/3600:.1f} hr)")
    logger.info(f"Total LLM time: {final_stats['total_request_time']:.1f}s ({final_stats['total_request_time']/60:.1f} min)")
    logger.info(f"LLM % of total: {(final_stats['total_request_time']/total_execution_time)*100:.1f}%")
    logger.info(f"Projects completed: {len(completed_projects)}/{len(project_names)}")
    logger.info(f"Total LLM requests: {final_stats['request_count']}")
    logger.info(f"Avg time per project: {total_execution_time/len(completed_projects)/60:.1f} min" if project_names else "N/A")
    logger.info(f"Full report saved to: {report_file_path}")
    logger.info("="*60)

if __name__ == "__main__":
    main()