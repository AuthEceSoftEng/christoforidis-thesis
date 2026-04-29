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
import json
from .LLM import LLMHandler
from .prompts import decide_cwes_prompt

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

    llm = LLMHandler(model='claude', temperature=0.2)
    messages = decide_cwes_prompt(project_name, readme_content, package_content)
    response = llm.send_message(messages)

    return [int(num.strip()) for num in response.split(',')]
    
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

def cwes_to_check(project_name: str, extra_folder: str = None):
    """
    Build the full list of CWEs to scan for by combining LLM and advisory sources.

    Args:
        project_name: Name of the project directory.
        extra_folder: Optional subdirectory within codebases/.

    Returns:
        Sorted, deduplicated list of integer CWE IDs from both sources.
    """
    llm_cwes = llm_decides_cwes(project_name, extra_folder)

    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'output', project_name, 'methods_vulnerable.json'), 'r') as f:
            methods_vulnerable = json.load(f)
        methods_cwes = cwes_from_vulnerable_methods(methods_vulnerable)
    except (FileNotFoundError, json.JSONDecodeError):
        methods_cwes = []
    
    # Combine and deduplicate CWEs
    return sorted(list(set(llm_cwes) | set(methods_cwes)))