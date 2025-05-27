import os
from utils.query_runner import run_codeql_query_tables
from utils.node_post_process import process_nodes, nodes_to_json
from utils.create_db import create_codeql_database
from utils.methods_post_process import deduplicate_methods, methods_to_json, compare_with_advisories, classify_vulnerable_methods

def main():
    ## CODEQL DATABASE CREATION ##
    project_name = "juice-shop" # temporary project name

    # create codeql database or use existing one
    success, message = create_codeql_database(project_name)
    if not success:
        print(f"Error creating CodeQL database: {message}")
        return
    
    # get the database path
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
    database_path = os.path.join(project_root, "databases", project_name)

    # set the output directory
    output_dir = os.path.join(project_root, "output", project_name)
    os.makedirs(output_dir, exist_ok=True)

    """ ## SOURCE EXTRACTION ##
    # Define the paths for the query and output files
    query_path = os.path.join(project_root, "codeql", "getSources.ql")
    results_path = os.path.join(output_dir, "sources")

    # Run the CodeQL query to extract sources
    success, error = run_codeql_query_tables(database_path, query_path, results_path)
    if not success:
        print(f"Error running source extraction query: {error}")
        return
    print(f"Source extraction completed. Results saved to {results_path}.csv")

    # process sources using the process_nodes function from utils/node_post_process.py
    processed_sources = process_nodes(f"{results_path}.csv", "source", f"{results_path}_processed.csv")

    # turn csv to json using the node_to_json function from utils/node_post_process.py
    sources_json = nodes_to_json(processed_sources, "source", f"{results_path}.json", project_name) # leave this as is for now

    ## SINK EXTRACTION ##
    # Define the paths for the query and output files
    query_path = os.path.join(project_root, "codeql", "getSinks.ql")
    results_path = os.path.join(output_dir, "sinks")

    # Run the CodeQL query to extract sinks
    success, error = run_codeql_query_tables(database_path, query_path, results_path)
    if not success:
        print(f"Error running sink extraction query: {error}")
        return
    print(f"Sink extraction completed. Results saved to {results_path}.csv")

    # process sinks using the process_nodes function from utils/node_post_process.py
    processed_sinks = process_nodes(f"{results_path}.csv", "sink", f"{results_path}_processed.csv")

    # turn csv to json using the nodes_to_json function from utils/node_post_process.py
    sinks_json = nodes_to_json(processed_sinks, "sink", f"{results_path}.json", project_name) # leave this as is for now """

    ## EXTRACT METHODS FROM DEPENDENCIES ##
    query_path = os.path.join(project_root, "codeql", "getPackageMethods.ql")
    results_path = os.path.join(output_dir, "methods")

    # run the CodeQL query to extract methods from dependencies
    success, error = run_codeql_query_tables(database_path, query_path, results_path)
    if not success:
        print(f"Error running methods extraction query: {error}")
        return
    print(f"Methods extraction completed. Results saved to {results_path}.csv")
    
    # deduplicate the df in case codeql returns duplicates
    processed_methods = deduplicate_methods(f"{results_path}.csv", f"{results_path}_processed.csv")

    # turn csv to json
    methods_json = methods_to_json(processed_methods, f"{results_path}.json")

    # check for vulnerable npm packages
    vulnerable_packages = compare_with_advisories(methods_json, output_path=f"{results_path}_vulnerable.json")

    # classify vulnerable methods
    classified_methods = classify_vulnerable_methods(vulnerable_packages, f"{results_path}_vulnerable_classified.json")

if __name__ == "__main__":
    main()