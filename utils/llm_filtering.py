"""
LLM-based false positive filtering for CodeQL vulnerability findings.

After CodeQL produces raw vulnerability detections, this module sends each
finding (along with surrounding source code context) to the LLM for a
confidence assessment. Findings below a configurable threshold are filtered
out as likely false positives.

Provides two modes:
  - filter_llm_findings(): Live filtering that calls the LLM for each finding
  - filter_with_existing_responses(): Re-filter using previously saved LLM responses
    at different confidence thresholds without re-invoking the LLM
"""

import pandas as pd
import os
import logging
import json

from .general import get_smart_context_range, extract_context_from_file, extract_line
from .prompts import get_vulnerability_confidence
from .LLM import LLMHandler

logger = logging.getLogger(__name__)

def filter_llm_findings(project_name, csv_path, filtered_csv_path, threshold = 0.6, response_output_path = None):
    """
    Filter CodeQL findings using LLM-based confidence scoring.

    For each finding in the CSV, extracts the surrounding source code context
    (using smart AST-based range detection), sends it to the LLM with the
    vulnerability details, and parses the confidence score from the response.
    Findings below the threshold are filtered out as likely false positives.

    Args:
        project_name: Name of the project (used to locate source files).
        csv_path: Path to the CSV file with raw CodeQL findings.
        filtered_csv_path: Path to write the filtered CSV output.
        threshold: Minimum confidence score to retain a finding (default 0.6).
        response_output_path: Optional path to save raw LLM responses for later re-filtering.
    """
    # Initialize LLM handler
    llm_handler = LLMHandler('claude', temperature=0.2)

    responses = []
    filtered_rows = []
    
    results = pd.read_csv(csv_path, header=None)
    logger.info(f"Processing {len(results)} findings from {csv_path}")

    for idx, row in results.iterrows():
        query_name = row[0]
        description = row[3]
        relative_path = row[4]
        source_line = row[5]
        sink_line = row[7]

        file_path = os.path.join(os.path.dirname(__file__), "..", "codebases", project_name, relative_path.lstrip('/\\'))

        # get context
        start, end = get_smart_context_range(file_path, sink_line, project_name)
        context = extract_context_from_file(file_path, start, end, sink_line)

        source_expression = extract_line(file_path, source_line)
        sink_expression = extract_line(file_path, sink_line)

        # get llm confidence score
        confidence_prompt = get_vulnerability_confidence(context, file_path, source_line, source_expression, sink_line, sink_expression, query_name, description)
        confidence_response = llm_handler.send_message(confidence_prompt)
        responses.append(confidence_response)

        # parse json response
        try:
            # Clean response (remove potential markdown blocks)
            clean_response = confidence_response.strip()
            if clean_response.startswith('```'):
                clean_response = clean_response.split('```')[1]
                if clean_response.startswith('json'):
                    clean_response = clean_response[4:]
                clean_response = clean_response.strip()
            
            result = json.loads(clean_response)
            confidence = float(result.get("confidence", 0.0))
            verdict = result.get("verdict", "UNKNOWN")
            reasoning = result.get("reasoning", "")

            logger.info(f"[{idx+1}/{len(results)}] {relative_path}:{sink_line} - "
                       f"Confidence: {confidence:.2f}, Verdict: {verdict}")
            
            # keep if above threshold or insufficient context
            if confidence >= threshold or verdict == "INSUFFICIENT_CONTEXT":
                filtered_rows.append(row)
                logger.debug(f"Retained finding: {relative_path}:{sink_line} - Reasoning: {reasoning}, Confidence: {confidence:.2f}, Verdict: {verdict}")
            else:
                logger.debug(f"Filtered out finding: {relative_path}:{sink_line} - Reasoning: {reasoning}, Confidence: {confidence:.2f}, Verdict: {verdict}")

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response for row {idx}: {e}")
            logger.debug(f"Response was: {confidence_response[:100]}")
            # On parse error, keep the finding (conservative approach)
            filtered_rows.append(row)

    # Write responses to output file (json)
    if response_output_path:
        with open(response_output_path, 'w', encoding='utf-8') as f:
            for response in responses:
                f.write(response + "\n")
        logger.info(f"Wrote LLM responses to {response_output_path}")

    # Write filtered results to new CSV
    if filtered_rows:
        filtered_df = pd.DataFrame(filtered_rows)
        filtered_df.to_csv(filtered_csv_path, index=False, header=False)
        logger.info(f"Wrote filtered findings to {filtered_csv_path} ({len(filtered_rows)} findings retained)")
    else:
        logger.warning("No findings retained after filtering; no output CSV created.")
def filter_with_existing_responses(csv_path, responses_json_path, filtered_csv_path, threshold=0.6):
    """
    Filter findings using pre-existing LLM responses from a JSON file.
    Each line in the JSON file corresponds to a row in the CSV file.
    
    Args:
        csv_path: Path to the CSV file with findings
        responses_json_path: Path to the JSON file with LLM responses (one per line)
        filtered_csv_path: Path where filtered CSV will be saved
        threshold: Confidence threshold for filtering (default 0.6)
    """
    filtered_rows = []
    
    results = pd.read_csv(csv_path, header=None)
    logger.info(f"Processing {len(results)} findings from {csv_path}")
    
    # Read all responses from JSON file
    with open(responses_json_path, 'r', encoding='utf-8') as f:
        responses = [line.strip() for line in f if line.strip()]
    
    if len(responses) != len(results):
        logger.warning(f"Mismatch: {len(results)} CSV rows but {len(responses)} JSON responses")
        # Use minimum to avoid index errors
        num_entries = min(len(responses), len(results))
    else:
        num_entries = len(results)
    
    for idx in range(num_entries):
        row = results.iloc[idx]
        confidence_response = responses[idx]
        
        relative_path = row[4]
        sink_line = row[7]
        
        # Parse JSON response
        try:
            # Clean response (remove potential markdown blocks)
            clean_response = confidence_response.strip()
            if clean_response.startswith('```'):
                clean_response = clean_response.split('```')[1]
                if clean_response.startswith('json'):
                    clean_response = clean_response[4:]
                clean_response = clean_response.strip()
            
            result = json.loads(clean_response)
            confidence = float(result.get("confidence", 0.0))
            verdict = result.get("verdict", "UNKNOWN")
            reasoning = result.get("reasoning", "")
            
            logger.info(f"[{idx+1}/{num_entries}] {relative_path}:{sink_line} - "
                       f"Confidence: {confidence:.2f}, Verdict: {verdict}")
            
            # Keep if above threshold or insufficient context
            if confidence >= threshold or verdict == "INSUFFICIENT_CONTEXT":
                filtered_rows.append(row)
                logger.debug(f"Retained finding: {relative_path}:{sink_line} - Reasoning: {reasoning}, Confidence: {confidence:.2f}, Verdict: {verdict}")
            else:
                logger.debug(f"Filtered out finding: {relative_path}:{sink_line} - Reasoning: {reasoning}, Confidence: {confidence:.2f}, Verdict: {verdict}")
        
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response for row {idx}: {e}")
            logger.debug(f"Response was: {confidence_response[:100]}")
            # On parse error, keep the finding (conservative approach)
            filtered_rows.append(row)
    
    # Write filtered results to new CSV
    if filtered_rows:
        filtered_df = pd.DataFrame(filtered_rows)
        filtered_df.to_csv(filtered_csv_path, index=False, header=False)
        logger.info(f"Wrote filtered findings to {filtered_csv_path} ({len(filtered_rows)} findings retained)")
    else:
        logger.warning("No findings retained after filtering; no output CSV created.")