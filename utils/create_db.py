"""
CodeQL database creation from JavaScript/Node.js source code.

Wraps the `codeql database create` CLI command to build a CodeQL database
from a target project's source code. The database is stored in the
`databases/` directory and is required before any CodeQL queries can be run.

Handles existing database detection (prompts for overwrite), thread
configuration, and error reporting.
"""

import os
import subprocess
import logging
import time
from typing import Tuple, Optional
import shutil
from dotenv import load_dotenv
load_dotenv()

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_codeql_database(source_path: str,
                           output_path: str = None,
                           language: str = "javascript",
                           threads: int = None,
                           response: str = None) -> Tuple[bool, Optional[str], float]:
    """
    Create a CodeQL database from source code.

    Performance is controlled by three environment variables (same as query_runner.py):

        CODEQL_THREADS=0      Threads for the extractor (0 = all cores).
                              The JS extractor propagates this as LGTM_THREADS.
        CODEQL_RAM=10240      MB hint passed to the extractor JVM via -M.
                              The JS extractor uses half for the TypeScript
                              compiler (LGTM_TYPESCRIPT_RAM).
        CODEQL_DISK_CACHE=4096  MB for the on-disk predicate cache.

    JavaScript-specific optimisation:
        node_modules/ is excluded from extraction via the
        ``javascript.index.filters`` extractor option.  Indexing node_modules
        adds significant time and database size without improving analysis
        quality for the queries in this pipeline (which target first-party code
        and use advisory data for third-party package classification).

    Args:
        source_path:  Path to the source code directory (codebases/{project}).
        output_path:  Path to save the CodeQL database.  Defaults to
                      databases/{project_name}.
        language:     Source language.  Defaults to "javascript".
        threads:      Override thread count.  When None, reads CODEQL_THREADS
                      (default 0 = all cores).
        response:     Pre-supplied answer ('y'/'n') for the existing-database
                      prompt (avoids interactive input in automated runs).

    Returns:
        (success, error_message | None, elapsed_seconds)
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

    # Resolve performance settings from env vars (same vars as query_runner.py)
    _threads    = threads if threads is not None else int(os.environ.get("CODEQL_THREADS",    "0"))
    _ram_mb     = int(os.environ.get("CODEQL_RAM",        "4096"))
    _cache_mb   = int(os.environ.get("CODEQL_DISK_CACHE", "2048"))

    # command to create the CodeQL database
    _codeql_bin = os.environ.get("CODEQL_BIN", "codeql")

    command = [
        _codeql_bin,
        "database", "create", output_path,
        f"--language={language}",
        f"--source-root={full_source_path}",
        f"--threads={_threads}",
        f"--ram={_ram_mb}",
        f"--max-disk-cache={_cache_mb}",
    ]

    # JavaScript-specific: exclude node_modules from extraction.
    # node_modules can contain thousands of files and adds significant time
    # and DB size without improving analysis of first-party code.
    if language == "javascript":
        command += [
            "--extractor-option=javascript.index.filters=exclude:**/node_modules/**",
        ]
    
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