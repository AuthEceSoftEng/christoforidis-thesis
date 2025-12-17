import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.llm_filtering import filter_llm_findings, filter_with_existing_responses

project_name = "juice-shop"
threshold = 0.6

csv_path = rf"C:\Projects\thesis\output\{project_name}_callgraphs1\{project_name}\deduplicated.csv"
filtered_csv_path = rf"C:\Projects\thesis\output\{project_name}_callgraphs1\{project_name}\filtered{str(int(threshold*100))}_deduplicated.csv"
response_output_path = rf"C:\Projects\thesis\output\{project_name}_callgraphs1\{project_name}\llm_responses.json"

#filter_llm_findings(project_name, csv_path, filtered_csv_path, threshold=threshold, response_output_path=response_output_path)
filter_with_existing_responses(csv_path, response_output_path, filtered_csv_path, threshold=threshold)