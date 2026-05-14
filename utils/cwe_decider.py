"""
CWE selection logic for determining which vulnerabilities to scan for.

Combines two strategies to build a comprehensive list of CWEs to check:
  1. LLM-based: Analyzes the project's README.md and package.json to infer
     plausible CWE categories.
  2. Advisory-based: Extracts CWE IDs from GitHub Security Advisories that
     matched the project's vulnerable dependencies.

The final list is the union of both sources, deduplicated and sorted.
"""

import os
import re
import json
import logging
from .LLM import LLMHandler
from .prompts import decide_cwes_prompt

logger = logging.getLogger(__name__)

def llm_decides_cwes(project_name: str, extra_folder: str = None):
    """
    Use the LLM to identify applicable CWEs based on project metadata.

    Reads the project's README.md and package.json, sends them to Claude,
    and parses the response into a list of integer CWE IDs.

    Args:
        project_name: Name of the project directory in codebases/.
        extra_folder: Optional subdirectory within codebases/ (e.g., for CVE evaluation).

    Returns:
        List of integer CWE IDs identified by the LLM.
    """
    try:
        if extra_folder is None:
            readme_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', project_name, 'README.md')
        else:
            readme_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', extra_folder, project_name, 'README.md')
            if not os.path.exists(readme_path):
                # Fall back to parent folder README (e.g. codebases/sgarden/README.md)
                readme_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', extra_folder, 'README.md')
        with open(readme_path, 'r', encoding='utf-8') as file:
            readme_content = file.read()
    except FileNotFoundError:
        readme_content = "No README found for this project."

    try:
        if extra_folder is None:
            package_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', project_name, 'package.json')
        else:
            package_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', extra_folder, project_name, 'package.json')
        with open(package_path, 'r', encoding='utf-8') as file:
            package_content = file.read()
    except FileNotFoundError:
        package_content = "No package.json found for this project."

    llm = LLMHandler(temperature=0.2)
    messages = decide_cwes_prompt(project_name, readme_content, package_content)
    response = llm.send_message(messages)

    # Extract all integers from the response (handles "CWE-XX", plain numbers, mixed text)
    all_numbers = [int(n) for n in re.findall(r'\b(\d+)\b', response)]
    # Keep only plausible CWE IDs (1–1275, matching registry max) and deduplicate
    cwes = sorted(set(n for n in all_numbers if 1 <= n <= 1275))
    if not cwes:
        logger.error(f"LLM returned no parseable CWE IDs. Raw response: {response!r}")
    else:
        logger.info(f"LLM identified {len(cwes)} CWEs from response")
    return cwes
    
def cwes_from_vulnerable_methods(methods_vulnerable):
    """
    Extract unique CWE IDs from the advisory data of vulnerable methods.

    Args:
        methods_vulnerable: Single dict or list of dicts containing advisory CWE info.

    Returns:
        Sorted list of unique integer CWE IDs.
    """
    unique_cwes = set()
    
    # Handle single dictionary or list of dictionaries
    if isinstance(methods_vulnerable, dict):
        methods_vulnerable = [methods_vulnerable]
        
    for vulnerability in methods_vulnerable:
        # Extract CWEs from the advisory section
        if 'advisory' in vulnerability and 'cwes' in vulnerability['advisory']:
            for cwe in vulnerability['advisory']['cwes']:
                if 'cwe_id' in cwe:
                    # Remove 'CWE-' prefix if present and convert to integer
                    cwe_id = cwe['cwe_id'].replace('CWE-', '')
                    try:
                        unique_cwes.add(int(cwe_id))
                    except ValueError:
                        # Skip if CWE ID is not a valid integer
                        continue
    
    # Convert set to sorted list for consistent output
    return sorted(list(unique_cwes))

def registry_cwes() -> set:
    """Return the set of CWE IDs that have queries in the registry."""
    registry_path = os.path.join(os.path.dirname(__file__), '..', 'codeql', 'registry.json')
    with open(registry_path, 'r') as f:
        registry = json.load(f)
    return set(int(k) for k in registry.keys())

def cwes_to_check(project_name: str, extra_folder: str = None):
    """
    Build the full list of CWEs to scan for by combining LLM and advisory sources,
    filtered to only those supported by the registry.

    - LLM CWEs are intersected with the registry (only scannable CWEs kept).
    - Advisory CWEs are kept as-is regardless of registry (grounded in real vulns).

    Args:
        project_name: Name of the project directory.
        extra_folder: Optional subdirectory within codebases/.

    Returns:
        Sorted, deduplicated list of integer CWE IDs from both sources.
    """
    supported = registry_cwes()

    llm_cwes = llm_decides_cwes(project_name, extra_folder)
    llm_cwes_filtered = [c for c in llm_cwes if c in supported]
    skipped = len(llm_cwes) - len(llm_cwes_filtered)
    if skipped:
        logger.info(f"Filtered {skipped} LLM CWEs not in registry (kept {len(llm_cwes_filtered)})")

    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'output', project_name, 'methods_vulnerable.json'), 'r') as f:
            methods_vulnerable = json.load(f)
        methods_cwes = cwes_from_vulnerable_methods(methods_vulnerable)
    except (FileNotFoundError, json.JSONDecodeError):
        methods_cwes = []

    # LLM CWEs filtered to registry; advisory CWEs kept as-is
    return sorted(list(set(llm_cwes_filtered) | set(methods_cwes)))