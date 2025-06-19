import os
import logging
import pandas as pd

# set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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

    # read csv
    csv_path = os.path.join(os.path.dirname(__file__), "..", "docs", "cwes.csv")
    df = pd.read_csv(csv_path, index_col=False)

    df['CWE-ID'] = df['CWE-ID'].astype(str).str.strip()
    
    # check if cwe_id is in the dataframe
    if str(cwe_id) in df['CWE-ID'].astype(str).values:
        return {
            "id": cwe_id,
            "name": df.loc[df['CWE-ID'].astype(str) == str(cwe_id), 'Name'].values[0],
            "description": df.loc[df['CWE-ID'].astype(str) == str(cwe_id), 'Description'].values[0],
        }
    else:
        logger.warning(f"CWE ID {cwe_id} not found in the dataframe.")
        return {
            "id": cwe_id,
            "name": f"CWE{cwe_id}Vulnerability",
            "description": "No description available."
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