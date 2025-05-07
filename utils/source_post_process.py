import os
import pandas as pd
import logging

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def process_sources(csv_path: str, output_path: str = None) -> pd.DataFrame:
    # deduplicate sources using the deduplicate_sources_context function
    deduplicated = deduplicate_sources_context(csv_path)
    if deduplicated is not None:
        print(f"Deduplication completed.")
    else:
        print("Deduplication failed.")

    full_expressions = extract_full_expressions(deduplicated, output_path)
    if full_expressions is not None:
        print(f"Full expressions extraction completed.")
    else:
        print("Full expressions extraction failed.")
    return full_expressions

def deduplicate_sources_context(csv_path: str, output_path: str = None) -> pd.DataFrame:
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

    # create unique identifier for each source
    df['source_id'] = df.apply(
        lambda row: f"{os.path.basename(row['location'])}:{row['startLine']}:{row['startColumn']}:{row['category']}:{row['expression']}",
        axis=1
    )
    
    # calculate context length
    df['context_size'] = df['contextEnd'] - df['contextStart']

    # sort by context size (descending) and drop duplicates
    df.sort_values(by='context_size', ascending=False)
    deduplicated = df.drop_duplicates(subset=['source_id'])

    # remove the temporary 'source_id' and 'context_size' columns
    deduplicated = deduplicated.drop(columns=['source_id', 'context_size'], axis=1)

    new_count = len(deduplicated)
    logger.info(f"Removed {original_count - new_count} duplicates. Remaining sources: {new_count}")

    # save the deduplicated DataFrame to a new CSV file if output_path is provided
    if output_path:
        deduplicated.to_csv(output_path, index=False)
        logger.info(f"Deduplicated sources saved to: {output_path}")

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
