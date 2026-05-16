import logging
import os
import sys
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.scraper import clone_vulnerable_repos
from utils.create_db import create_codeql_database
from utils.query_runner import run_codeql_query_tables
from utils.methods_post_process import deduplicate_methods, methods_to_json, compare_with_advisories, classify_vulnerable_methods
from utils.query_generator import generate_codeql_package_classification, generate_conditional_sanitizer_library, cleanup_test_queries, refine_vulnerability_query
from utils.cwe_decider import cwes_to_check
from utils.query_runner import run_codeql_path_problem

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    cves_folder = os.path.join(os.path.dirname(__file__), "mini_evaluation")
    codebases_folder = os.path.join(os.path.dirname(__file__), "..", "codebases", "mini_cloned_repos")
    project_root = os.path.join(os.path.dirname(__file__), "..")

    clone_vulnerable_repos(cves_folder, codebases_folder)

    project_names = [name for name in os.listdir(codebases_folder) if os.path.isdir(os.path.join(codebases_folder, name))]
    logger.info(f"Cloned repositories for evaluation: {project_names}")

    for project_name in project_names:
        project_path = os.path.join(codebases_folder, project_name)
        logger.info(f"Processing project: {project_name}")
        
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
        generate_conditional_sanitizer_library(classified_methods, qll_path, validation_db=project_name)

        cleanup_test_queries(project_specific_dir)

        # decide CWEs to check
        cwes = cwes_to_check(project_name, extra_folder="mini_cloned_repos")
        logger.info(f"CWEs to check for {project_name}: {cwes}")

        # refine vulnerability query for each CWE
        def _refine_one_cwe(cwe_id):
            output_path = os.path.join(project_root, 'codeql', 'general', f'cwe_{cwe_id}_vulnerability_final.ql')
            if not os.path.exists(output_path):
                refine_vulnerability_query(cwe_id, project_name, general=True)
            else:
                src = output_path
                dst = os.path.join(project_specific_dir, f'cwe_{cwe_id}_vulnerability_final.ql')
                shutil.copy2(src, dst)

        max_workers = min(len(cwes), int(os.environ.get("CWE_WORKERS", "8")))
        logger.info(f"Processing {len(cwes)} CWEs with {max_workers} parallel workers")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_refine_one_cwe, cwe_id): cwe_id for cwe_id in cwes}
            for future in as_completed(futures):
                future.result()  # re-raises any unexpected exception

    for project_name in project_names:
        project_specific_dir = os.path.join(project_root, "codeql", "project_specific", project_name)
        queries = [f for f in os.listdir(project_specific_dir) if f.endswith('final.ql')]

        database_path = os.path.join(project_root, "databases", project_name)

        for query in queries:
            query_path = os.path.join(project_root, "codeql", "project_specific", project_name, query)
            output_path = os.path.join(project_root, "output", "mini_evaluation", project_name, query)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            run_codeql_path_problem(database_path, query_path, output_path)
    
if __name__ == "__main__":
    main()