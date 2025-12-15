import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.llm_filtering import filter_llm_findings

csv_path = r"C:\Projects\thesis\output\dvna_callgraphs1\dvna\deduplicated.csv"
filtered_csv_path = r"C:\Projects\thesis\output\dvna_callgraphs1\dvna\filtered_deduplicated.csv"
response_output_path = r"C:\Projects\thesis\output\dvna_callgraphs1\dvna\llm_responses.json"

filter_llm_findings(csv_path, filtered_csv_path, threshold=0.6, response_output_path=response_output_path)