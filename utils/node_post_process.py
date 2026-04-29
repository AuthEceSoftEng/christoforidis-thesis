"""
Post-processing of CodeQL source/sink node extraction results.

Handles the full processing pipeline for extracted nodes:
  1. Deduplication by context (keeps entries with the most context lines)
  2. Full expression extraction (resolves truncated '...' expressions by
     reading the original source files)
  3. Deduplication by expression (keeps the longest full expression)
  4. Context range validation (ensures ranges stay within file boundaries,
     trims oversized contexts, centers around the node line)
  5. Conversion to JSON format with highlighted context text
"""

import json
import os
import pandas as pd
import logging
from utils.general import extract_context_from_file

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def process_nodes(csv_path: str, node_type: str, output_path: str = None) -> pd.DataFrame:
    # deduplicate nodes using the deduplicate_nodes_context function
    deduplicated_context = deduplicate_nodes_context(csv_path, node_type)
    if deduplicated_context is not None:
        print(f"Deduplication by context completed.")
    else:
        print("Deduplication failed.")
        return

    # extract full expressions using the extract_full_expressions function
    full_expressions = extract_full_expressions(deduplicated_context)
    if full_expressions is not None:
        print(f"Full expressions extraction completed.")
    else:
        print("Full expressions extraction failed.")
        return
    
    # deduplicate by expression using the deduplicate_by_expression function
    deduplicated_expressions = deduplicate_by_expression(full_expressions, node_type)
    if deduplicated_expressions is not None:
        print(f"Deduplication by expression completed.")
    else:
        print("Deduplication by expression failed.")
        return
    
    # validate context ranges using the validate_context_ranges function
    validated_context = validate_context_ranges(deduplicated_expressions)
    if validated_context is not None:
        print(f"Context validation completed.")
    else:
        print("Context validation failed.")
        return
    
    nodes = validated_context.copy() # this should change if we process more

    # add id column
    logger.info("Adding id column")
    nodes['id'] = nodes.apply(
        lambda row: f"{"SRC" if node_type == "source" else "SNK"}-{os.path.basename(row['location']).split('.')[0]}-L{int(row['startLine'])}-C{int(row['startColumn'])}",
        axis=1
    )

    if output_path:
        nodes.to_csv(output_path, index=False)
        logger.info(f"Processed {node_type}s saved to: {output_path}")
    
    return nodes

def deduplicate_nodes_context(csv_path: str, node_type: str, output_path: str = None) -> pd.DataFrame:
    """
    Read a CSV file of CodeQL query results amd remove duplicates,
    keeping the entry with the most context lines.
    
    Args:
        csv_path (str): Path to the input CSV file.
        output_path (str, optional): Path to save the deduplicated CSV file.

    Returns:
        pd.DataFrame: DataFrame containing the deduplicated results.
    """

    logger.info(f"Reading CSV file: {csv_path}")
    df = pd.read_csv(csv_path, header = 0)
    original_count = len(df)

    # create unique identifier for each node
    df['id'] = df.apply(
        lambda row: f"{os.path.basename(row['location'])}:{row['startLine']}:{row['startColumn']}:{row['category']}:{row['expression']}",
        axis=1
    )
    
    # calculate context length
    df['context_size'] = df['contextEnd'] - df['contextStart']

    # sort by context size (descending) and drop duplicates
    df = df.sort_values(by='context_size', ascending=False)
    deduplicated = df.drop_duplicates(subset=['id'])

    # remove the temporary 'id' and 'context_size' columns
    deduplicated = deduplicated.drop(columns=['id', 'context_size'], axis=1)

    new_count = len(deduplicated)
    logger.info(f"Removed {original_count - new_count} duplicates based on context. Remaining {node_type}s: {new_count}")

    # save the deduplicated DataFrame to a new CSV file if output_path is provided
    if output_path:
        deduplicated.to_csv(output_path, index=False)
        logger.info(f"Deduplicated {node_type}s saved to: {output_path}")

    return deduplicated

def extract_full_expressions(df: pd.DataFrame, output_path: str = None) -> pd.DataFrame:
    """
    Extract full expressions by using prefix/suffix matching around truncated expressions.
    Only process expressions that contain '...'
    """
    logger.info("Extracting full expressions from truncated expressions")

    # check which entries need extraction
    df['needs_extraction'] = df['expression'].str.contains('...', regex=False)

    # count truncated expressions
    truncated_count = df['needs_extraction'].sum()
    logger.info(f"Found {truncated_count} truncated expressions.")

    # new column for full expressions
    df['full_expression'] = df['expression']

    # process rows that need extraction
    for idx, row in df[df['needs_extraction']].iterrows():
        try:
            file_path = row['location']
            line_num = int(row['startLine'])
            col_num = int(row['startColumn'])
            truncated_expr = row['expression']

            # get the prefix and suffix
            parts = truncated_expr.split('...')
            prefix = parts[0].strip()
            suffix = parts[-1].strip()

            # read the file and extract the full expression
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                    # convert to 0-indexed
                    line = lines[line_num - 1]
                    start_idx = col_num - 1

                    # try single-line extraction first
                    # verify prefix
                    if line[start_idx:].startswith(prefix):
                        # find suffix after prefix
                        suffix_pos = line.find(suffix, start_idx + len(prefix))
                        if suffix_pos > -1:
                            # extract the full expression
                            full_expr = line[start_idx:suffix_pos + len(suffix)]
                            df.at[idx, 'full_expression'] = full_expr
                            continue # if we found the full expression, skip to the next row

                    # if single-line extraction fails, try multi-line extraction
                    # read a block of lines
                    end_line = min(line_num + 5, len(lines))  # read up to 5 lines after the current line

                    first_line = lines[line_num-1]
                    start_idx = col_num - 1
                    if first_line[start_idx:].startswith(prefix):
                        # Extract from start position to end of first line
                        expr_start = first_line[start_idx:]
                        
                        # Search for suffix in the block
                        block_without_first = ''.join(lines[line_num:end_line])
                        suffix_pos = block_without_first.find(suffix)
                        
                        if suffix_pos > -1:
                            # Get text up to and including suffix
                            suffix_line_offset = block_without_first[:suffix_pos].count('\n')
                            suffix_line = lines[line_num + suffix_line_offset]
                            suffix_end_pos = suffix_line.find(suffix) + len(suffix)
                            
                            # Create the full expression
                            full_expr = expr_start.rstrip()
                            for i in range(line_num, line_num + suffix_line_offset):
                                full_expr += "\n" + lines[i].rstrip()
                            full_expr += "\n" + suffix_line[:suffix_end_pos]
                            
                            df.at[idx, 'full_expression'] = full_expr

            else:
                logger.warning(f"File not found: {file_path}. Skipping extraction for this entry.")

        except Exception as e:
            logger.error(f"Error extracting expression from {file_path}:{line_num}: {e}")

    # remove temporary 'needs_extraction' column
    df = df.drop(columns=['needs_extraction'])

    # save the updated DataFrame to a new CSV file if output_path is provided
    if output_path:
        df.to_csv(output_path, index=False)
        logger.info(f"Results with full expression saved to: {output_path}")

    return df

def deduplicate_by_expression(df: pd.DataFrame, node_type: str, output_path: str = None) -> pd.DataFrame:
    """
    Remove duplicate nodes keeping the entry with the largest full expression
    Should be used after the full expression extraction
    
    Args:
        df (pd.DataFrame): DataFrame with full_expression column from previous processing.
        output_path (str, optional): Path to save the deduplicated CSV file.

    Returns:
        pd.DataFrame: DataFrame containing the deduplicated results.
    """
    logger.info("Deduplicating by full expression")
    original_count = len(df)

    # create unique identifier for each source
    df['location_id'] = df.apply(
        lambda row: f"{os.path.basename(row['location'])}:{row['startLine']}:{row['startColumn']}",
        axis = 1
    )

    # calculate expression length
    df['expr_length'] = df['full_expression'].str.len()

    # sort by location_id and expression length (descending) and drop duplicates
    df = df.sort_values(by=['location_id', 'expr_length'], ascending=[True, False])
    deduplicated = df.drop_duplicates(subset=['location_id'], keep='first')

    # remove the temporary 'location_id' and 'expr_length' columns
    deduplicated = deduplicated.drop(columns=['location_id', 'expr_length'])

    new_count = len(deduplicated)
    logger.info(f"Removed {original_count - new_count} duplicates based on expressions. Remaining {node_type}s: {new_count}")

    if output_path:
        deduplicated.to_csv(output_path, index=False)
        logger.info(f"Deduplicated {node_type}s saved to: {output_path}")

    return deduplicated

def validate_context_ranges(df: pd.DataFrame, max_context_lines: int = 20, output_path: str = None) -> pd.DataFrame:
    """
    Validate and improve context ranges
    1. Ensure context doesn't exceed file boundaries
    2. Trim large context ranges to a maximum size
    3. Make sure source line is always included in the context
    
    Args:
        df (pd.DataFrame): DataFrame with source results.
        max_context_lines (int): Maximum number of context lines to keep (default 20).

    Returns:
        pd.DataFrame: DataFrame with validated context ranges.
    """

    logger.info("Validating and correcting context ranges")
    
    # process each row
    for idx, row in df.iterrows():
        try:
            file_path = row['location']
            start_line = int(row['startLine'])
            context_start = int(row['contextStart'])
            context_end = int(row['contextEnd'])

            # check if file exists
            if not os.path.exists(file_path):
                logger.warning(f"File not found: {file_path}. Skipping this entry.")
                continue

            # get the file lines
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines = sum(1 for _ in f)

            corrected_start = max(1, context_start) # context start doesnt start before line 1
            corrected_end = min(total_lines, context_end) # context end doesnt exceed file length

            # ensure the node line is within the context range
            corrected_start = min(corrected_start, start_line)
            corrected_end = max(corrected_end, start_line)

            # if only one line of context, add 5 lines before and after the node line
            if corrected_start == corrected_end:
                corrected_start = max(1, start_line - 5)
                corrected_end = min(total_lines, start_line + 5)


            # trim oversized context ranges
            context_size = corrected_end - corrected_start + 1
            if context_size > max_context_lines:
                # center the context around the node line
                lines_before = min(max_context_lines // 2, start_line - 1)
                lines_after = max_context_lines - lines_before - 1

                corrected_start = start_line - lines_before
                corrected_end = min(total_lines, start_line + lines_after)

                # if we are at the end shift lines before
                if corrected_end < start_line + lines_after:
                    additional_lines = start_line + lines_after - corrected_end
                    corrected_start = max(1, corrected_start - additional_lines)

                # if we are at the beginning shift lines after
                if corrected_start == 1 and (corrected_end - corrected_start + 1) < max_context_lines:
                    additional_lines = max_context_lines - (corrected_end - corrected_start + 1)
                    corrected_end = min(total_lines, corrected_end + additional_lines)

            # update df
            df.at[idx, 'contextStart'] = corrected_start
            df.at[idx, 'contextEnd'] = corrected_end

        except Exception as e:
            logger.error(f"Error validating context ranges for {row['location']}:{row['startLine']}: {e}")

    # save the updated DataFrame to a new CSV file if output_path is provided
    if output_path:
        df.to_csv(output_path, index=False)
        logger.info(f"Results with validated contexts saved to: {output_path}")

    return df

def nodes_to_json(df: pd.DataFrame, node_type: str, output_path: str = None, project_name = None) -> list:
    """
    Convert nodes DataFrame to JSON format.

    Args:
        df (pd.DataFrame): DataFrame containing node information.
        output_path (str, optional): Path to save the JSON file.
    
    Returns:
        list: list of node objects.
    """

    logger.info(f"Converting {node_type}s to JSON format")

    nodes = []
    for idx, row in df.iterrows():
        try:
            # extract info from df
            start_line = int(row['startLine'])
            start_column = int(row['startColumn'])
            context_start = int(row['contextStart'])
            context_end = int(row['contextEnd'])
            expression = row['full_expression']
            file_path = row['location']

            # create file path without machine specific info
            if project_name:
                # find project name in path and get everything after it
                project_name_index = file_path.find(project_name)
                if project_name_index != -1:
                    short_path = file_path[project_name_index + len(project_name) + 1:]
                else:
                    # if project name not found, use file name only
                    short_path = os.path.basename(file_path)
            else:
                # if project name is not provided, use file name only
                short_path = os.path.basename(file_path)

            # extract context with highlighted node line
            context_text = extract_context_from_file(
                file_path = file_path,
                context_start = context_start,
                context_end = context_end,
                highlight_line = start_line
            )

            # create node object
            node = {
                "id": row['id'],
                "location": {
                    "file": short_path,
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
            nodes.append(node)

        except Exception as e:
            logger.error(f"Error processing row {idx}: {e}")

    # save to json file if output_path is provided
    if output_path:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(nodes, f, indent=2, ensure_ascii=False)
            logger.info(f"{node_type}s saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving {node_type}s to JSON: {e}")

    return nodes