import json
import sys
from collections import defaultdict
from pathlib import Path

def load_njsscan_results(njsscan_file):
    with open(njsscan_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    results = []
    
    for rule_id, rule_data in data.get('nodejs', {}).items():
        for file_entry in rule_data.get('files', []):
            file_path = file_entry['file_path']
            match_lines = file_entry['match_lines']
            
            start_line = match_lines[0] if len(match_lines) > 0 else 0
            end_line = match_lines[1] if len(match_lines) > 1 else start_line
            
            results.append({
                'vulnerability': rule_data['metadata'].get('description', 'Unknown'),
                'check_id': rule_id,
                'file': file_path,
                'start_line': start_line,
                'end_line': end_line,
                'severity': rule_data['metadata'].get('severity', 'INFO'),
                'cwe': rule_data['metadata'].get('cwe', 'Unknown')
            })
    
    for rule_id, rule_data in data.get('templates', {}).items():
        for file_entry in rule_data.get('files', []):
            file_path = file_entry['file_path']
            match_lines = file_entry['match_lines']
            
            start_line = match_lines[0] if len(match_lines) > 0 else 0
            end_line = match_lines[1] if len(match_lines) > 1 else start_line
            
            results.append({
                'vulnerability': rule_data['metadata'].get('description', 'Unknown'),
                'check_id': rule_id,
                'file': file_path,
                'start_line': start_line,
                'end_line': end_line,
                'severity': rule_data['metadata'].get('severity', 'INFO'),
                'cwe': rule_data['metadata'].get('cwe', 'Unknown')
            })
    
    return results

def load_ground_truth(json_file):
    with open(json_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def normalize_path(path):
    path = str(Path(path).as_posix())
    if path.startswith('./'):
        path = path[2:]
    elif path.startswith('/'):
        path = path[1:]
    return path

def paths_match(njsscan_path, gt_path):
    njsscan_normalized = normalize_path(njsscan_path)
    gt_normalized = normalize_path(gt_path)
    
    return (njsscan_normalized.endswith(gt_normalized) or 
            gt_normalized.endswith(njsscan_normalized) or
            njsscan_normalized == gt_normalized)

def line_in_range(line, start, end):
    return start <= line <= end

def analyze_vulnerabilities(njsscan_data, ground_truth):
    
    gt_map = defaultdict(lambda: defaultdict(list))
    
    for challenge_name, data in ground_truth.items():
        file_path = data['file']
        for line in data['vulnLines']:
            gt_map[file_path][line].append({
                'challenge': challenge_name,
                'startLine': data['startLine'],
                'endLine': data['endLine']
            })
    
    true_positives_dict = {}
    false_positives = []
    found_vulns = set()
    
    for detection in njsscan_data:
        file_path = detection['file']
        start_line = detection['start_line']
        end_line = detection['end_line']
        vulnerability = detection['vulnerability']
        
        if not file_path or start_line == 0:
            continue
        
        matching_challenges = []
        matched_line = None
        matched_gt_file = None
        
        for gt_file, lines_dict in gt_map.items():
            if paths_match(file_path, gt_file):
                for vuln_line, challenges in lines_dict.items():
                    matched = False
                    
                    # vuln line is within detection
                    if line_in_range(vuln_line, start_line, end_line):
                        matched = True
                    
                    # end line is within ground truth range
                    if not matched:
                        for challenge_info in challenges:
                            gt_start = challenge_info['startLine']
                            gt_end = challenge_info['endLine']
                            
                            if line_in_range(end_line, gt_start, gt_end):
                                matched = True
                                break
                    
                    if matched:
                        matching_challenges = challenges
                        matched_line = vuln_line
                        matched_gt_file = gt_file
                        break
                
                if matching_challenges:
                    break
        
        if matching_challenges:
            key = (matched_gt_file, matched_line)
            
            if key not in true_positives_dict:
                challenge_names = [c['challenge'] for c in matching_challenges]
                
                true_positives_dict[key] = {
                    'file': file_path,
                    'ground_truth_file': matched_gt_file,
                    'source_line': start_line,
                    'sink_line': end_line,
                    'matched_line': matched_line,
                    'vulnerability': vulnerability[:200],
                    'check_id': detection['check_id'],
                    'challenges': challenge_names,
                    'detection_count': 1
                }
                found_vulns.add(f"{matched_gt_file}:{matched_line}")
            else:
                true_positives_dict[key]['detection_count'] += 1
        else:
            false_positives.append({
                'file': file_path,
                'source_line': start_line,
                'sink_line': end_line,
                'vulnerability': vulnerability[:200],
                'check_id': detection['check_id']
            })
    
    true_positives = list(true_positives_dict.values())
    
    false_negatives = []
    for file_path, lines_dict in gt_map.items():
        for line_num, challenges in lines_dict.items():
            key = f"{file_path}:{line_num}"
            if key not in found_vulns:
                challenge_names = [c['challenge'] for c in challenges]
                false_negatives.append({
                    'file': file_path,
                    'line': line_num,
                    'challenges': challenge_names
                })
    
    return true_positives, false_positives, false_negatives

def calculate_metrics(tp, fp, fn):
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
    
    print("\n" + "="*80)
    print("NJSSCAN VULNERABILITY ANALYSIS RESULTS")
    print("="*80)
    
    print("\nSUMMARY METRICS:")
    print(f"  True Positives:  {metrics['true_positives']}")
    print(f"  False Positives: {metrics['false_positives']}")
    print(f"  False Negatives: {metrics['false_negatives']}")
    print(f"  Precision:       {metrics['precision']}%")
    print(f"  Recall:          {metrics['recall']}%")
    print(f"  F1 Score:        {metrics['f1_score']}%")
    
    print("\n" + "="*80)
    print(f"TRUE POSITIVES ({len(tp)})")
    print("="*80)
    for item in tp:
        print(f"  {item['file']}")
        print(f"     Lines: {item['source_line']}-{item['sink_line']}")
        print(f"     Matched ground truth line: {item['matched_line']}")
        print(f"     Challenges: {', '.join(item['challenges'])}")
        print(f"     Check ID: {item['check_id']}")
        print(f"     Vulnerability: {item['vulnerability'][:80]}...")
        if item.get('detection_count', 1) > 1:
            print(f"     Detected {item['detection_count']} times (duplicates removed)")
        print()
    
    print("="*80)
    print(f"FALSE POSITIVES ({len(fp)})")
    print("="*80)
    for item in fp:
        print(f"  {item['file']}")
        print(f"     Lines: {item['source_line']}-{item['sink_line']}")
        print(f"     Check ID: {item['check_id']}")
        print(f"     Vulnerability: {item['vulnerability'][:80]}...")
        print()
    
    print("="*80)
    print(f"FALSE NEGATIVES ({len(fn)})")
    print("="*80)
    for item in fn:
        print(f"  {item['file']}:{item['line']}")
        print(f"     Challenges: {', '.join(item['challenges'])}")
        print()

def save_to_json(tp, fp, fn, metrics, output_file):
    results = {
        'metrics': metrics,
        'true_positives': tp,
        'false_positives': fp,
        'false_negatives': fn
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python analyze_njsscan_results.py <report_njsscan.json> <ground_truth.json> [output.json]")
        sys.exit(1)
    
    njsscan_file = sys.argv[1]
    gt_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    print(f"Loading njsscan results from: {njsscan_file}")
    njsscan_data = load_njsscan_results(njsscan_file)
    print(f"Loaded {len(njsscan_data)} detections")
    
    print(f"Loading ground truth from: {gt_file}")
    ground_truth = load_ground_truth(gt_file)
    
    unique_lines = set()
    for data in ground_truth.values():
        for line in data['vulnLines']:
            unique_lines.add((data['file'], line))
    
    print(f"Loaded {len(ground_truth)} challenges with {len(unique_lines)} unique vulnerable lines")
    
    print("\nAnalyzing vulnerabilities...")
    tp, fp, fn = analyze_vulnerabilities(njsscan_data, ground_truth)
    metrics = calculate_metrics(tp, fp, fn)
    
    print_results(tp, fp, fn, metrics)
    
    if output_file:
        save_to_json(tp, fp, fn, metrics, output_file)

if __name__ == "__main__":
    main()