import os
import logging
import json
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


def sources_to_json(df: pd.DataFrame, output_path: str = None) -> list:
    """
    Convert sources DataFrame to JSON format.

    Args:
        df (pd.DataFrame): DataFrame containing source information.
        output_path (str, optional): Path to save the JSON file.
    
    Returns:
        list: list of source objects.
    """

    logger.info("Converting sources to JSON format")

    sources = []
    for idx, row in df.iterrows():
        try:
            # extract info from df
            file_path = row['location']
            start_line = int(row['startLine'])
            start_column = int(row['startColumn'])
            context_start = int(row['contextStart'])
            context_end = int(row['contextEnd'])
            expression = row['full_expression']

            # extract context with highlighted source line
            context_text = extract_context_from_file(
                file_path = file_path,
                context_start = context_start,
                context_end = context_end,
                highlight_line = start_line
            )

            # create source object
            source = {
                "id": row['source_id'],
                "location": {
                    "file": file_path,
                    "line": start_line,
                    "column": start_column
                },
                "category": row['category'],
                "expression": expression,
                "context": {
                    "start_line": context_start,
                    "end_line": context_end,
                    "text": context_text
                }
            }
            sources.append(source)

        except Exception as e:
            logger.error(f"Error processing row {idx}: {e}")

    # save to json file if output_path is provided
    if output_path:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(sources, f, indent=2, ensure_ascii=False)
            logger.info(f"Sources saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving sources to JSON: {e}")

    return sources