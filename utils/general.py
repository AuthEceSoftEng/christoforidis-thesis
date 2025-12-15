import os
import logging
import pandas as pd
import requests
import tempfile
import esprima
from collections import defaultdict
from .query_runner import run_codeql_query_tables
from . prompts import keywords_filter_prompt

# set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_smart_context_range(file_path, sink_line, max_buffer=50):
    """Find statement/function boundaries around sink_line using JS parsing"""
    full_path = os.path.join(os.path.dirname(__file__), "codebases", "dvna", file_path.lstrip('/\\'))
    
    # Read file first for fallback
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        lines = code.split('\n')
        total_lines = len(lines)
    except Exception as e:
        logger.warning(f"Could not read file {full_path}: {e}")
        return max(1, sink_line - 15), sink_line + 15
    
    # Only attempt parsing for .js and .ts files
    if file_path.endswith(('.js', '.ts', '.jsx', '.tsx')):
        try:
            tree = esprima.parseScript(code, {'loc': True, 'tolerant': True})
            
            # Find meaningful context nodes (prefer functions/statements)
            candidates = []
            
            def walk(node):
                if hasattr(node, 'loc') and node.loc:
                    node_start = node.loc.start.line
                    node_end = node.loc.end.line
                    
                    if node_start <= sink_line <= node_end:
                        # Prioritize meaningful node types
                        node_type = node.type if hasattr(node, 'type') else 'Unknown'
                        priority = 0
                        
                        if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                            priority = 3
                        elif node_type in ['ExpressionStatement', 'VariableDeclaration', 'CallExpression']:
                            priority = 2
                        elif node_type in ['BlockStatement', 'Program']:
                            priority = 1
                        
                        size = node_end - node_start
                        candidates.append((priority, size, node_start, node_end))
                
                for key, value in node.__dict__.items():
                    if isinstance(value, list):
                        for item in value:
                            if hasattr(item, '__dict__'):
                                walk(item)
                    elif hasattr(value, '__dict__'):
                        walk(value)
            
            walk(tree)
            
            if candidates:
                # Sort by priority (high first), then size (small first)
                candidates.sort(key=lambda x: (-x[0], x[1]))
                _, _, best_start, best_end = candidates[0]
                
                # Ensure minimum context size
                if best_end - best_start < 5:
                    best_start = max(1, sink_line - 10)
                    best_end = min(total_lines, sink_line + 10)
                
                logger.debug(f"✓ Parsed {file_path}:{sink_line} -> {best_start}-{best_end}")
                return best_start, best_end
                
        except Exception as e:
            logger.debug(f"Parse failed for {file_path}: {str(e)[:50]}")
    else:
        logger.debug(f"Skipping parse for {file_path} (template/non-JS file)")
    
    # Fallback to simple buffer with bounds checking
    return max(1, sink_line - 15), min(total_lines, sink_line + 15)

def extract_context_from_file(file_path: str, context_start: int, context_end: int, highlight_line: int = None) -> str:
    """
    Extart context text from a file given the start and end line numbers.

    Args:
        file_path (str): Path to the file.
        context_start (int): Start line number for context extraction. (1-based index).
        context_end (int): End line number for context extraction. (1-based index).

    Returns:
        str: Extracted context text (or empty if not found).
    """
    if not os.path.exists(file_path):
        logger.error(f"File does not exist: {file_path}")
        return ""
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Adjust for 0-based index
        start_idx = max(0, context_start - 1)
        end_idx = min(len(lines), context_end)

        # ensure start and end indices are within bounds
        if start_idx >= len(lines) or end_idx <= 0 or start_idx >= end_idx:
            logger.warning(f"Invalid line range: {context_start}-{context_end} in file: {file_path}")
            return ""
        
        # extract the context
        context_lines = lines[start_idx:end_idx]

        # highlight the line if specified
        if highlight_line is not None and context_start <= highlight_line <= context_end:
            highlight_idx = highlight_line - context_start
            if 0 <= highlight_idx < len(context_lines):
                context_lines[highlight_idx] = f"→ {context_lines[highlight_idx]}"

        return ''.join(context_lines)
    
    except Exception as e:
        logger.error(f"Error extracting context from {file_path}: {e}")
        return ""
    
def get_cwe_details(cwe_id):
    logger.info(f"Fetching details for CWE ID: {cwe_id}")

    url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id}"

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        name = data['Weaknesses'][0]['Name']
        description = data['Weaknesses'][0]['Description']
    else:
        logger.warning(f"Error: {response.status_code} fetching CWE details for ID {cwe_id}.")
        name = f"CWE{cwe_id}Vulnerability"
        description = "No description available."

    return {
        "id": cwe_id,
        "name": name,
        "description": description,
    }
    
def extract_predicate_from_file(file_path: str, predicate_name: str) -> str:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        predicate_lines = []
        in_predicate = False
        brace_count = 0

        for line in lines:
            if not in_predicate and line.strip().startswith(f"predicate {predicate_name}"):
                in_predicate = True
                predicate_lines.append(line)
                brace_count += line.count('{')
                continue
            if in_predicate:
                predicate_lines.append(line)
                brace_count += line.count('{')
                brace_count -= line.count('}')
                if brace_count == 0:
                    break
        
        if predicate_lines:
            return ''.join(predicate_lines)
        return None
    
    except Exception as e:
        logger.error(f"Error extracting predicate from {file_path}: {e}")
        return None
    
def extract_call_graph(database_path: str, project_name: str, include_frontend: bool = True) -> pd.DataFrame:
    """
    Extract call graph from a CodeQL database and return as DataFrame.
    
    This provides project-specific structural information about:
    - Function call relationships
    - Route handlers and their calls
    - Database operation functions
    - Validation/sanitization functions
    
    Args:
        database_path: Path to the CodeQL database
        project_name: Name of the project (for logging)
        include_frontend: Whether to include frontend/client code (default: False)
        
    Returns:
        DataFrame with columns: caller_file, caller_name, call_name, line
        Returns None if extraction fails
    """
    logger.info(f"Extracting call graph for project: {project_name}")
    
    # Path to the call graph extraction query
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    query_path = os.path.join(base_dir, "codeql", "extractCallGraph.ql")
    
    # Create temp output directory
    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = os.path.join(temp_dir, "call_graph_results")
        
        # Run the query
        success, error, _ = run_codeql_query_tables(database_path, query_path, output_path)
        
        if not success:
            logger.error(f"Failed to extract call graph: {error}")
            return None
        
        # Parse CSV results
        csv_path = f"{output_path}.csv"
        if not os.path.exists(csv_path):
            logger.error("Call graph CSV file not found")
            return None
        
        try:
            # Read the CSV
            df = pd.read_csv(csv_path)
            
            # Filter frontend if needed
            if not include_frontend:
                frontend_patterns = ['frontend/', 'client/', 'public/', 'views/', 'test/', 'spec.', '.test.', 'cypress/']
                mask = ~df['caller_file'].str.lower().str.contains('|'.join(frontend_patterns), na=False)
                df = df[mask]
            
            logger.info(f"Extracted {len(df)} call relationships for {project_name}")
            return df
            
        except Exception as e:
            logger.error(f"Error parsing call graph results: {str(e)}")
            return None

def format_call_graph_for_cwe(df: pd.DataFrame, cwe_id: int, project_name: str, max_results: int = 500) -> str:
    """
    Format call graph data for a specific CWE, focusing on relevant patterns.
    Uses LLM to dynamically determine relevant keywords based on CWE description.
    
    Args:
        df: DataFrame with call graph data
        cwe_id: CWE ID to focus on
        project_name: Project name for logging
        max_results: Maximum number of results to include in output
        
    Returns:
        Formatted string for LLM prompt
    """
    if df is None or len(df) == 0:
        return None
    
    from .LLM import LLMHandler
    
    # Get CWE details
    cwe_details = get_cwe_details(cwe_id)
    
    # Ask LLM to identify relevant keywords for filtering call graph
    llm = LLMHandler('claude', temperature=0.1)
    
    keyword_prompt = keywords_filter_prompt(cwe_id, cwe_details)
    
    keywords_str = llm.send_message(keyword_prompt).strip()
    keywords = [k.strip().lower() for k in keywords_str.split(',')]
    
    logger.info(f"LLM identified keywords for CWE-{cwe_id}: {keywords}")
    
    # Filter by keywords if available
    if keywords:
        pattern = '|'.join(keywords)
        filtered_df = df[df['call_name'].str.lower().str.contains(pattern, na=False, case=False)]
        logger.info(f"Filtered call graph for CWE-{cwe_id}: {len(filtered_df)} relevant calls (from {len(df)} total)")
    else:
        # No keywords identified, use all but limit
        filtered_df = df
        logger.info(f"No specific filters for CWE-{cwe_id}, using all {len(df)} calls")
    
    # If too few results, fall back to showing all
    if len(filtered_df) < 10 and len(df) > len(filtered_df):
        logger.warning(f"Only {len(filtered_df)} filtered results for CWE-{cwe_id}, falling back to all calls")
        filtered_df = df
    
    # Limit results
    if len(filtered_df) > max_results:
        filtered_df = filtered_df.head(max_results)
        logger.info(f"Limited to {max_results} results for CWE-{cwe_id}")
    
    # Format for output
    if len(filtered_df) == 0:
        return None
    
    return _format_call_graph_summary(filtered_df, project_name, cwe_id)

def _format_call_graph_summary(df: pd.DataFrame, project_name: str, cwe_id: int = None) -> str:
    """
    Format call graph data into a concise summary for LLM consumption.
    
    Args:
        df: DataFrame with call graph data
        project_name: Project name
        cwe_id: Optional CWE ID for context
    """
    summary_lines = [
        f"=== CALL GRAPH STRUCTURE FOR: {project_name} ===",
    ]
    
    if cwe_id:
        summary_lines.append(f"Filtered for CWE-{cwe_id} relevant patterns")
    
    summary_lines.append("")
    
    # Group by caller file and function
    call_groups = defaultdict(lambda: defaultdict(list))
    
    for _, row in df.iterrows():
        caller_file = row.get('caller_file', '')
        caller_name = row.get('caller_name', '<anonymous>')
        call_name = row.get('call_name', '')
        
        if caller_file and call_name:
            call_groups[caller_file][caller_name].append(call_name)
    
    # Categorize files (same as before)
    routes = {}
    controllers = {}
    models = {}
    core = {}
    utils = {}
    config = {}
    other = {}
    
    for file_path, functions in call_groups.items():
        file_lower = file_path.lower()
        if any(keyword in file_lower for keyword in ['route', 'router', 'endpoint']):
            routes[file_path] = functions
        elif any(keyword in file_lower for keyword in ['controller', 'handler', 'api']):
            controllers[file_path] = functions
        elif any(keyword in file_lower for keyword in ['model', 'schema', 'entity']):
            models[file_path] = functions
        elif any(keyword in file_lower for keyword in ['core', 'lib', 'service']):
            core[file_path] = functions
        elif any(keyword in file_lower for keyword in ['util', 'helper', 'common']):
            utils[file_path] = functions
        elif any(keyword in file_lower for keyword in ['config', 'setup', 'server']):
            config[file_path] = functions
        else:
            other[file_path] = functions
    
    # Format each category
    def format_category(category_name, files_dict, max_files=8, max_functions=12):
        if not files_dict:
            return []
        
        lines = [f"\n### {category_name} ({len(files_dict)} files)"]
        
        for i, (file_path, functions) in enumerate(list(files_dict.items())[:max_files]):
            lines.append(f"\n{file_path}:")
            for func_name, calls in list(functions.items())[:max_functions]:
                # Deduplicate and limit calls
                unique_calls = list(set(calls))[:10]
                calls_str = ", ".join(unique_calls)
                lines.append(f"  {func_name}() → calls: {calls_str}")
            
            if len(functions) > max_functions:
                lines.append(f"  ... and {len(functions) - max_functions} more functions")
        
        if len(files_dict) > max_files:
            lines.append(f"\n  ... and {len(files_dict) - max_files} more {category_name.lower()} files")
        
        return lines
    
    # Add categories
    summary_lines.extend(format_category("ROUTES/ENDPOINTS", routes, max_files=10))
    summary_lines.extend(format_category("CONTROLLERS/HANDLERS", controllers, max_files=8))
    summary_lines.extend(format_category("CORE/SERVICES", core, max_files=6))
    summary_lines.extend(format_category("MODELS/SCHEMAS", models, max_files=5))
    summary_lines.extend(format_category("CONFIG/SETUP", config, max_files=3))
    summary_lines.extend(format_category("UTILITIES", utils, max_files=3))
    summary_lines.extend(format_category("OTHER", other, max_files=3))
    
    # Add summary statistics
    total_files = sum([len(routes), len(controllers), len(core), len(models), len(config), len(utils), len(other)])
    summary_lines.extend([
        "",
        "=== SUMMARY ===",
        f"Files analyzed: {total_files}",
        f"Call relationships shown: {len(df)}",
        f"Routes/Endpoints: {len(routes)} files (entry points for user input)",
        f"Controllers/Handlers: {len(controllers)} files (request processing)",
        ""
    ])
    
    return "\n".join(summary_lines)