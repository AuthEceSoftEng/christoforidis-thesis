import os
import subprocess
import logging
import time
from typing import Tuple, Optional
import shutil

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_codeql_database(source_path: str,
                           output_path: str = None,
                           language: str = "javascript",
                           threads: int = 0, 
                           response: str = None) -> Tuple[bool, Optional[str], float]:
    """
    Create a CodeQL database from source code.
    
    Args:
        source_path (str): Path to the source code directory codebases/{project_name}.
        output_path (str, optional): Path to save the CodeQL database. If None creates in databases/{project_name}.
        language (str, optional): Language of the source code. Defaults to "javascript".
        threads (int, optional): Number of threads to use. Defaults to 0 (auto-detect).

    Returns:
        Tuple[bool, Optional[str], float]: Success status, error message if any, and execution time.
    """
    start_time = time.time()

    # project root directory (parent of utils)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # validate source_path
    full_source_path = source_path
    if not os.path.isabs(source_path):
        full_source_path = os.path.join(project_root, "codebases", source_path)
    if not os.path.exists(full_source_path):
        return False, f"Source path does not exist: {full_source_path}", 0.0
    
    # determine output path
    if not output_path:
        project_name = os.path.basename(os.path.normpath(full_source_path))
        output_path = os.path.join(project_root, "databases", project_name)
    elif not os.path.isabs(output_path):
        output_path = os.path.join(project_root, "databases", output_path)

    # create output directory if it doesn't exist
    os.makedirs(output_path, exist_ok=True)

    # check if the database already exists
    if os.path.exists(output_path) and os.path.isdir(output_path) and os.listdir(output_path):  # Check if dir exists and is not empty
        # Ask user what to do
        print(f"\nDatabase already exists at: {output_path}")
        while True:
            if response is None:
                response = input("Do you want to remove and recreate it? (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                logger.info(f"Removing existing database at {output_path}")
                try:
                    shutil.rmtree(output_path)
                    # Recreate the empty directory
                    os.makedirs(output_path, exist_ok=True)
                    break
                except Exception as e:
                    return False, f"Failed to remove existing database: {str(e)}", time.time() - start_time
            elif response in ['n', 'no']:
                logger.info(f"Keeping existing database at {output_path}")
                return True, "Using existing database", 0.0 # return success without creating a new one, script ends here
            else:
                response = input("Please enter 'y' or 'n'")

    # command to create the CodeQL database
    command = [
        "codeql", "database", "create", output_path,
        f"--language={language}",
        f"--source-root={full_source_path}",
    ]

    # add threads option if specified
    if threads > 0:
        command.append(f"--threads={threads}")
    
    # execute the command
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        execution_time = time.time() - start_time
        logger.info(f"CodeQL database created successfully at {output_path} in {execution_time:.1f}s")
        return True, None, execution_time
    
    except subprocess.CalledProcessError as e:
        error_msg = f"Error creating CodeQL database: {e.stderr}"
        logger.error(error_msg)
        return False, error_msg, time.time() - start_time