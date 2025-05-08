import json
import logging
import pandas as pd

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def deduplicate_methods(csv_path: str, output_path: str = None) -> pd.DataFrame:
    """
    Deduplicate methods dataframe based on packageName, version, and methodName.
    
    Args:
        csv_path (str): Path to the input CSV file.
        output_path (str, optional): Path to save the deduplicated CSV file.

    Returns:
        pd.DataFrame: Deduplicated DataFrame.
    """
    try:
        # read csv file
        df = df = pd.read_csv(csv_path, header = 0)

        # drop duplicates
        unique_df = df.drop_duplicates(["packageName", "version", "methodName"])

        # sort for readability
        unique_df = unique_df.sort_values(by=["packageName", "methodName"])

        # Save to CSV if output path is provided
        if output_path:
            unique_df.to_csv(output_path, index=False)
            logger.info(f"Deduplicated methods saved to {output_path}")
        
        return unique_df
    
    except Exception as e:
        logger.error(f"Error deduplicating methods: {e}")
        raise

def methods_to_json(df: pd.DataFrame, output_path: str = None) -> list:
    """
    Convert methods DataFrame to JSON format.
    
    Args:
        df (pd.DataFrame): DataFrame containing methods
        output_path (str, optional): Path to save the JSON file.
        
    Returns:
        list: list of method objects
    """

    methods = []

    for (package_name, version), group in df.groupby(["packageName", "version"]):
        package = {
            "package": package_name,
            "version": version,
            "methods": group['methodName'].tolist()
        }
        methods.append(package)

    # Save to JSON if output path is provided
    if output_path:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(methods, f, indent=2, ensure_ascii=False)
            logger.info(f"Methods saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving methods to JSON: {e}")
