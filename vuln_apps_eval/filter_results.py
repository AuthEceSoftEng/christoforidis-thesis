import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.llm_filtering import filter_llm_findings

project_name = "juice-shop"

csv_path = rf"C:\Projects\thesis\output\{project_name}_callgraphs1\{project_name}\deduplicated.csv"
filtered_csv_path = rf"C:\Projects\thesis\output\{project_name}_callgraphs1\{project_name}\filtered_deduplicated.csv"
response_output_path = rf"C:\Projects\thesis\output\{project_name}_callgraphs1\{project_name}\llm_responses.json"

filter_llm_findings(project_name, csv_path, filtered_csv_path, threshold=0.6, response_output_path=response_output_path)