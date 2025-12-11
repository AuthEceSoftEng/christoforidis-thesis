import os
import subprocess
import logging
import time
from typing import Optional, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_codeql_query_tables(database_path: str, query_path: str, output_path: str) -> Tuple[bool, Optional[str], float]:
    """
    Run a CodeQL query on a given database and save results to CSV.
    for @kind table
    first run the query and save the results to a bqrs file
    then decode the bqrs file to csv

    Args:
        database_path (str): Path to the CodeQL database.
        query_path (str): Path to the CodeQL query file.
        output_path (str): Path to save the output results.

    Returns:
        Tuple of (success_status, error_message or None, execution_time).
    """
    start_time = time.time()

    # Check if the database path exists
    if not os.path.exists(database_path):
        return False, f"Database path does not exist: {database_path}", 0.0

    # Check if the query path exists
    if not os.path.exists(query_path):
        return False, f"Query path does not exist: {query_path}", 0.0

    # Construct the command to run the CodeQL query
    command_run = [
        "codeql", "query", "run",
        f"--database={database_path}",
        f"--output={output_path}.bqrs",
        query_path
    ]
    logger.info(f"Running CodeQL query: {' '.join(command_run)}")

    # decode the bqrs file to csv
    command_decode = [
        "codeql", "bqrs", "decode",
        f"--output={output_path}.csv",
        "--format=csv",
        f"{output_path}.bqrs"
    ]
    logger.info(f"Running CodeQL query: {' '.join(command_decode)}")

    try:
        # execute the command_run
        result = subprocess.run(
            command_run,
            check=True,
            text=True,
            capture_output=True
        )

        logger.info(f"Query completed successfully. Results saved to {output_path}.bqrs")

        try:
            # execute the command_decode
            result = subprocess.run(
                command_decode,
                check=True,
                text=True,
                capture_output=True
            )

            logger.info(f"Query completed successfully. Results saved to {output_path}.csv")
            
            end_time = time.time()
            execution_time = end_time - start_time
            return True, None, execution_time
        
        except subprocess.CalledProcessError as e:
            error_msg = f"CodeQL query failed with exit code {e.returncode}: {e.stderr}"
            logger.error(error_msg)
            return False, error_msg, time.time() - start_time
        
        except Exception as e:
            error_msg = f"An unexpected error occurred running the CodeQL query: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, time.time() - start_time
    
    except subprocess.CalledProcessError as e:
        error_msg = f"CodeQL query failed with exit code {e.returncode}: {e.stderr}"
        logger.error(error_msg)
        return False, error_msg, time.time() - start_time
    
    except Exception as e:
        error_msg = f"An unexpected error occurred running the CodeQL query: {str(e)}"
        logger.error(error_msg)
        return False, error_msg, time.time() - start_time
    
def run_codeql_path_problem(database_path: str, query_path: str, output_path: str) -> Tuple[bool, Optional[str], float]:
    """
    Run a CodeQL path-problem query on a given database and save results to SARIF.
    For @kind path-problem queries, which show data flow paths.
    
    Args:
        database_path (str): Path to the CodeQL database.
        query_path (str): Path to the CodeQL query file.
        output_path (str): Path to save the output results (without extension).
    
    Returns:
        Tuple of (success_status, error_message or None, execution_time).
    """
    start_time = time.time()
    
    # Check if the database path exists
    if not os.path.exists(database_path):
        return False, f"Database path does not exist: {database_path}", 0.0
    
    # Check if the query path exists
    if not os.path.exists(query_path):
        return False, f"Query path does not exist: {query_path}", 0.0
    
    # For path-problem queries, we use database analyze to generate SARIF
    sarif_output = f"{output_path}.sarif"
    command_analyze = [
        "codeql", "database", "analyze",  "--rerun",
        database_path,
        query_path,
        "--format=sarif-latest",
        f"--output={sarif_output}"
    ]
    logger.info(f"Running CodeQL path-problem query: {' '.join(command_analyze)}")
    
    try:
        # Execute the analysis with direct SARIF output
        result = subprocess.run(
            command_analyze,
            check=True,
            text=True,
            capture_output=True
        )
        logger.info(f"Path-problem analysis completed successfully. Results saved to {sarif_output}")
        
        # Additionally generate CSV for easier viewing of results
        csv_output = f"{output_path}.csv"
        command_csv = [
            "codeql", "database", "analyze", 
            database_path,
            query_path,
            "--format=csv",
            f"--output={csv_output}"
        ]
        
        try:
            csv_result = subprocess.run(
                command_csv,
                check=True,
                text=True,
                capture_output=True
            )
            logger.info(f"CSV results also generated: {csv_output}")
        except Exception as e:
            # Don't fail if CSV generation fails, just log it
            logger.warning(f"Could not generate CSV output: {str(e)}")
        
        end_time = time.time()
        execution_time = end_time - start_time
        return True, None, execution_time
        
    except subprocess.CalledProcessError as e:
        error_msg = f"CodeQL query failed with exit code {e.returncode}: {e.stderr}"
        logger.error(error_msg)
        return False, error_msg, time.time() - start_time
    
    except Exception as e:
        error_msg = f"An unexpected error occurred running the CodeQL query: {str(e)}"
        logger.error(error_msg)
        return False, error_msg, time.time() - start_time
    
def run_codeql_queries_batch(database_path: str, queries_dir: str, output_dir: str, threads: int = 0) -> Tuple[bool, Optional[str], float]:
    """
    Run multiple CodeQL queries in parallel using database analyze with threading.
    
    Args:
        database_path: Path to the CodeQL database
        queries_dir: Directory containing .ql query files
        output_dir: Directory to save output results
        threads: Number of threads (0 = all cores, -1 = all except 1)
    
    Returns:
        Tuple of (success_status, error_message or None, execution_time)
    """
    start_time = time.time()
    
    if not os.path.exists(database_path):
        return False, f"Database path does not exist: {database_path}", 0.0
    
    if not os.path.exists(queries_dir):
        return False, f"Queries directory does not exist: {queries_dir}", 0.0
    
    # Check if there are any queries
    query_files = [f for f in os.listdir(queries_dir) if f.endswith('.ql')]
    if not query_files:
        return False, f"No .ql files found in {queries_dir}", 0.0
    
    os.makedirs(output_dir, exist_ok=True)
    
    logger.info(f"Running {len(query_files)} queries in parallel with {threads if threads > 0 else 'all'} threads")
    
    # Use database analyze for batch execution with threading
    sarif_output = os.path.join(output_dir, "batch_results.sarif")
    command = [
        "codeql", "database", "analyze",
        f"--threads={threads}",
        "--rerun",
        database_path,
        queries_dir,  # Point to directory of queries
        "--format=sarif-latest",
        f"--output={sarif_output}"
    ]
    
    logger.info(f"Executing: {' '.join(command)}")
    
    try:
        result = subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=True
        )
        
        logger.info(f"Batch query execution completed. SARIF saved to {sarif_output}")
        
        # Also generate CSV output (decode SARIF or run again with CSV format)
        csv_output = os.path.join(output_dir, "batch_results.csv")
        command_csv = [
            "codeql", "database", "analyze",
            f"--threads={threads}",
            database_path,
            queries_dir,
            "--format=csv",
            f"--output={csv_output}"
        ]
        
        try:
            csv_result = subprocess.run(
                command_csv,
                check=True,
                text=True,
                capture_output=True
            )
            logger.info(f"CSV results saved to {csv_output}")
        except Exception as e:
            logger.warning(f"Could not generate CSV: {e}")
        
        end_time = time.time()
        execution_time = end_time - start_time
        return True, None, execution_time
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Batch query execution failed: {e.stderr}"
        logger.error(error_msg)
        return False, error_msg, time.time() - start_time
    
    except Exception as e:
        error_msg = f"Unexpected error during batch execution: {str(e)}"
        logger.error(error_msg)
        return False, error_msg, time.time() - start_time