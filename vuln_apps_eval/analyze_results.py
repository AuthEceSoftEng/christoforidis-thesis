"""
Vulnerability detection result analyzer.

Compares CodeQL detection results (CSV) against ground truth vulnerability
data (JSON) to compute standard security evaluation metrics:
  - True Positives (TP): Correctly identified vulnerabilities
  - False Positives (FP): Reported vulnerabilities that don't exist
  - False Negatives (FN): Missed vulnerabilities
  - Precision, Recall, and F1 Score

Matching logic supports two conditions:
  1. Exact line match: source or sink line matches a known vulnerable line
  2. Range match: source and sink span a known vulnerable code range

Usage:
    python analyze_results.py <csv_file> <json_ground_truth> [output.json]
"""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

def load_csv(csv_file):
    """Load and parse CSV file with vulnerability results (no headers).
    Column structure:
    - Column 0 (1st): Vulnerability type/name
    - Column 4 (5th): File path
    - Column 5 (6th): Source line
    - Column 7 (8th): Sink line
    """
    results = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        # Detect delimiter
        content = f.read()
        f.seek(0)
        
        if '\t' in content.split('\n')[0]:
            delimiter = '\t'
        else:
            delimiter = ','
        
        reader = csv.reader(f, delimiter=delimiter)
        
        for row in reader:
            if len(row) >= 8:  # Ensure we have enough columns
                results.append({
                    'vulnerability': row[0],
                    'file': row[4],
                    'source_line': row[5],
                    'sink_line': row[7]
                })
    
    return results

def load_json(json_file):
    """Load ground truth JSON file."""
    with open(json_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def normalize_path(path):
    """Normalize file paths for comparison.
    Removes leading ./ and converts to posix style.
    """
    path = str(Path(path).as_posix())
    # Remove leading ./
    if path.startswith('./'):
        path = path[2:]
    return path

def paths_match(csv_path, json_path):
    """Check if two paths refer to the same file.
    Handles cases where one path might be absolute and the other relative.
    """
    csv_normalized = normalize_path(csv_path)
    json_normalized = normalize_path(json_path)
    
    # Check if one path ends with the other (handles absolute vs relative)
    return (csv_normalized.endswith(json_normalized) or 
            json_normalized.endswith(csv_normalized) or
            csv_normalized == json_normalized)

def analyze_vulnerabilities(csv_data, json_data):
    """Compare CSV results against JSON ground truth."""
    
    # Build ground truth map: file -> dict of unique lines with all associated challenges
    ground_truth = defaultdict(lambda: defaultdict(list))
    
    for challenge_name, data in json_data.items():
        file_path = data['file']
        for line in data['vulnLines']:
            # Store all challenges associated with this line
            ground_truth[file_path][line].append({
                'challenge': challenge_name,
                'startLine': data['startLine'],
                'endLine': data['endLine']
            })
    
    # Track results - use dictionaries with unique keys to deduplicate
    true_positives_dict = {}  # key: (file, line) -> detection info
    false_positives = []
    found_vulns = set()
    
    # Analyze CSV detections
    for row in csv_data:
        file_path = row['file']
        vulnerability = row['vulnerability']
        
        # Parse source and sink lines
        try:
            source_line = int(row['source_line'])
            sink_line = int(row['sink_line'])
        except (ValueError, TypeError):
            continue
        
        if not file_path:
            continue
        
        # Check both conditions for matching
        matching_challenges = []
        matched_line = None
        matched_gt_file = None
        
        # Try to match against any ground truth file
        for gt_file, lines_dict in ground_truth.items():
            if paths_match(file_path, gt_file):
                # CONDITION 1: Check if source or sink line matches a vulnLine exactly
                if source_line in lines_dict:
                    matching_challenges = lines_dict[source_line]
                    matched_line = source_line
                    matched_gt_file = gt_file
                    break
                elif sink_line in lines_dict:
                    matching_challenges = lines_dict[sink_line]
                    matched_line = sink_line
                    matched_gt_file = gt_file
                    break
                
                # CONDITION 2: Check if both source and sink are within startLine-endLine range
                if not matching_challenges:
                    for vuln_line, challenges in lines_dict.items():
                        for challenge_info in challenges:
                            start = challenge_info['startLine']
                            end = challenge_info['endLine']
                            
                            # Check if both source and sink are within the range
                            if (start == source_line) and (sink_line == end):
                                matching_challenges = challenges
                                matched_line = vuln_line
                                matched_gt_file = gt_file
                                break
                        if matching_challenges:
                            break
                
                if matching_challenges:
                    break
        
        if matching_challenges:
            # Use a unique key to deduplicate
            key = (matched_gt_file, matched_line)
            
            # Only keep the first detection of this vulnerability
            if key not in true_positives_dict:
                # Collect all challenge names for this line
                challenge_names = [c['challenge'] for c in matching_challenges]
                
                true_positives_dict[key] = {
                    'file': file_path,
                    'ground_truth_file': matched_gt_file,
                    'source_line': source_line,
                    'sink_line': sink_line,
                    'matched_line': matched_line,
                    'vulnerability': vulnerability,
                    'challenges': challenge_names,  # All challenges for this line
                    'detection_count': 1
                }
                found_vulns.add(f"{matched_gt_file}:{matched_line}")
            else:
                # Increment counter for duplicate detections
                true_positives_dict[key]['detection_count'] += 1
        else:
            false_positives.append({
                'file': file_path,
                'source_line': source_line,
                'sink_line': sink_line,
                'vulnerability': vulnerability
            })
    
    # Convert dict back to list
    true_positives = list(true_positives_dict.values())
    
    # Find false negatives (missed vulnerabilities) - now deduplicated by line
    false_negatives = []
    for file_path, lines_dict in ground_truth.items():
        for line_num, challenges in lines_dict.items():
            key = f"{file_path}:{line_num}"
            if key not in found_vulns:
                # Collect all challenge names for this missed line
                challenge_names = [c['challenge'] for c in challenges]
                false_negatives.append({
                    'file': file_path,
                    'line': line_num,
                    'challenges': challenge_names
                })
    
    return true_positives, false_positives, false_negatives

def calculate_metrics(tp, fp, fn):
    """Calculate precision, recall, and F1 score."""
    tp_count = len(tp)
    fp_count = len(fp)
    fn_count = len(fn)
    
    precision = (tp_count / (tp_count + fp_count) * 100) if (tp_count + fp_count) > 0 else 0
    recall = (tp_count / (tp_count + fn_count) * 100) if (tp_count + fn_count) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
    
    return {
        'true_positives': tp_count,
        'false_positives': fp_count,
        'false_negatives': fn_count,
        'precision': round(precision, 2),
        'recall': round(recall, 2),
        'f1_score': round(f1, 2)
    }

def print_results(tp, fp, fn, metrics):
    """Print analysis results in a readable format."""
    
    print("\n" + "="*80)
    print("VULNERABILITY ANALYSIS RESULTS")
    print("="*80)
    
    print("\n📊 SUMMARY METRICS:")
    print(f"  True Positives:  {metrics['true_positives']}")
    print(f"  False Positives: {metrics['false_positives']}")
    print(f"  False Negatives: {metrics['false_negatives']}")
    print(f"  Precision:       {metrics['precision']}%")
    print(f"  Recall:          {metrics['recall']}%")
    print(f"  F1 Score:        {metrics['f1_score']}%")
    
    print("\n" + "="*80)
    print(f"✅ TRUE POSITIVES ({len(tp)})")
    print("="*80)
    for item in tp:
        print(f"  📄 {item['file']}")
        print(f"     Source line: {item['source_line']}, Sink line: {item['sink_line']}")
        print(f"     Matched ground truth line: {item['matched_line']}")
        print(f"     Challenges: {', '.join(item['challenges'])}")
        print(f"     Vulnerability: {item['vulnerability'][:80]}")
        if item.get('detection_count', 1) > 1:
            print(f"     ⚠️  Detected {item['detection_count']} times (duplicates removed)")
        print()
    
    print("="*80)
    print(f"❌ FALSE POSITIVES ({len(fp)})")
    print("="*80)
    for item in fp:
        print(f"  📄 {item['file']}")
        print(f"     Source line: {item['source_line']}, Sink line: {item['sink_line']}")
        print(f"     Vulnerability: {item['vulnerability'][:80]}")
        print()
    
    print("="*80)
    print(f"⚠️  FALSE NEGATIVES ({len(fn)})")
    print("="*80)
    for item in fn:
        print(f"  📄 {item['file']}:{item['line']}")
        print(f"     Challenges: {', '.join(item['challenges'])}")
        print()

def save_to_json(tp, fp, fn, metrics, output_file):
    """Save results to a JSON file."""
    results = {
        'metrics': metrics,
        'true_positives': tp,
        'false_positives': fp,
        'false_negatives': fn
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: {output_file}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python analyze_results.py <csv_file> <json_file> [output.json]")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    json_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Load data
    print(f"Loading CSV results from: {csv_file}")
    csv_data = load_csv(csv_file)
    print(f"Loaded {len(csv_data)} detections")
    
    print(f"Loading JSON ground truth from: {json_file}")
    json_data = load_json(json_file)
    
    # Count unique vulnerable lines (deduplicated)
    unique_lines = set()
    for data in json_data.values():
        for line in data['vulnLines']:
            unique_lines.add((data['file'], line))
    
    print(f"Loaded {len(json_data)} challenges with {len(unique_lines)} unique vulnerable lines")
    
    # Analyze
    print("\nAnalyzing vulnerabilities...")
    tp, fp, fn = analyze_vulnerabilities(csv_data, json_data)
    metrics = calculate_metrics(tp, fp, fn)
    
    # Print results
    print_results(tp, fp, fn, metrics)
    
    # Save to file if output specified
    if output_file:
        save_to_json(tp, fp, fn, metrics, output_file)

if __name__ == "__main__":
    main()