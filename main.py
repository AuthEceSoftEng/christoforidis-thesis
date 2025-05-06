import os
from utils.query_runner import run_codeql_query_tables

def main():
    database_path = "C:\\Projects\\codeql-dbs\\juice-shop" # temporary path to the database
    last_part = os.path.basename(database_path) #database name
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    os.makedirs(output_dir, exist_ok=True)  # Create output directory if it doesn't exist
    output_dir = os.path.join(output_dir, last_part)  # Create a subdirectory for the database
    os.makedirs(output_dir, exist_ok=True)  # Create subdirectory if it doesn't exist

    ## SOURCE EXTRACTION ##
    # Define the paths for the query and output files
    query_path = os.path.join(os.path.dirname(__file__), "codeql", "getSources.ql")
    results_path = os.path.join(output_dir, "sources")

    # Run the CodeQL query to extract sources
    success, error = run_codeql_query_tables(database_path, query_path, results_path)
    if not success:
        print(f"Error running source extraction query: {error}")
        return
    print(f"Source extraction completed. Results saved to {results_path}.csv")

if __name__ == "__main__":
    main()