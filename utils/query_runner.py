import os
import subprocess
import logging
from typing import Optional, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_codeql_query_tables(database_path: str, query_path: str, output_path: str) -> Tuple[bool, Optional[str]]:
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
        Tuple of (success_status, error_message or None).
    """

    # Check if the database path exists
    if not os.path.exists(database_path):
        return False, f"Database path does not exist: {database_path}"

    # Check if the query path exists
    if not os.path.exists(query_path):
        return False, f"Query path does not exist: {query_path}"

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

        logger.info(f"Query completed successfully. Results saved to {output_path}")

        try:
            # execute the command_decode
            result = subprocess.run(
                command_decode,
                check=True,
                text=True,
                capture_output=True
            )

            logger.info(f"Query completed successfully. Results saved to {output_path}")
            return True, None
        
        except subprocess.CalledProcessError as e:
            error_msg = f"CodeQL query failed with exit code {e.returncode}: {e.stderr}"
            logger.error(error_msg)
            return False, error_msg
        
        except Exception as e:
            error_msg = f"An unexpected error occurred running the CodeQL query: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    except subprocess.CalledProcessError as e:
        error_msg = f"CodeQL query failed with exit code {e.returncode}: {e.stderr}"
        logger.error(error_msg)
        return False, error_msg
    
    except Exception as e:
        error_msg = f"An unexpected error occurred running the CodeQL query: {str(e)}"
        logger.error(error_msg)
        return False, error_msg