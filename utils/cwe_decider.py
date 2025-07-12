import os
import json
from .LLM import LLMHandler
from .prompts import decide_cwes_prompt

def llm_decides_cwes(project_name: str, extra_folder: str = None):
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
    llm_cwes = llm_decides_cwes(project_name, extra_folder)

    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'output', project_name, 'methods_vulnerable.json'), 'r') as f:
            methods_vulnerable = json.load(f)
        methods_cwes = cwes_from_vulnerable_methods(methods_vulnerable)
    except (FileNotFoundError, json.JSONDecodeError):
        methods_cwes = []
    
    # Combine and deduplicate CWEs
    return sorted(list(set(llm_cwes) | set(methods_cwes)))