import os
from utils.query_runner import run_codeql_query_tables
from utils.source_post_process import process_sources
from utils.create_db import create_codeql_database
from utils.json_process import sources_to_json

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

    ## SOURCE EXTRACTION ##
    # Define the paths for the query and output files
    query_path = os.path.join(project_root, "codeql", "getSources.ql")
    results_path = os.path.join(output_dir, "sources")

    # Run the CodeQL query to extract sources
    success, error = run_codeql_query_tables(database_path, query_path, results_path)
    if not success:
        print(f"Error running source extraction query: {error}")
        return
    print(f"Source extraction completed. Results saved to {results_path}.csv")

    # process sources using the process_sources function from utils/source_post_process.py
    processed_sources = process_sources(f"{results_path}.csv", f"{results_path}_processed.csv")

    # turn csv to json using the sources_to_json function from utils/json_process.py
    sources_json = sources_to_json(processed_sources, f"{results_path}.json")
    

if __name__ == "__main__":
    main()