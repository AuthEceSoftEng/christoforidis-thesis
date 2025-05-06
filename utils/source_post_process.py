import os
import pandas as pd
import logging

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
        lambda row: f"{os.path.basename(row['location'])}:{row['startLine']}:{row['startColumn']}:{row['category']}",
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