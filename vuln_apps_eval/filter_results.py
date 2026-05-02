import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.llm_filtering import filter_llm_findings, filter_with_existing_responses

project_name = os.environ.get("PROJECT_NAME", "dvna")
threshold = 0.95

# Base output directory — defaults to current working directory if OUTPUT_DIR is not set
_output_dir = os.environ.get("OUTPUT_DIR") or os.getcwd()

csv_path = os.path.join(_output_dir, f"{project_name}_callgraphs1", project_name, "deduplicated.csv")
filtered_csv_path = os.path.join(_output_dir, f"{project_name}_callgraphs1", project_name, f"filtered{str(int(threshold*100))}_deduplicated.csv")
response_output_path = os.path.join(_output_dir, f"{project_name}_callgraphs1", project_name, "llm_responses.json")

#filter_llm_findings(project_name, csv_path, filtered_csv_path, threshold=threshold, response_output_path=response_output_path)
filter_with_existing_responses(csv_path, response_output_path, filtered_csv_path, threshold=threshold)