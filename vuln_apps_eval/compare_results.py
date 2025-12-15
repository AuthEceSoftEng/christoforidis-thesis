import json
import sys

def load_results(filepath):
    """Load results from JSON file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_tp_key(tp):
    """Create unique key for a true positive"""
    # Use file + sink_line as the unique identifier
    return (tp['file'], tp['sink_line'], tp.get('vulnerability', ''))

def compare_true_positives(file1, file2, output_file=None):
    """
    Compare true positives between two result files.
    Returns TPs in file1 that are NOT in file2.
    """
    results1 = load_results(file1)
    results2 = load_results(file2)
    
    # Get true positives from both files
    tps1 = results1.get('true_positives', [])
    tps2 = results2.get('true_positives', [])
    
    # Create sets of keys
    tps1_keys = {get_tp_key(tp): tp for tp in tps1}
    tps2_keys = {get_tp_key(tp) for tp in tps2}
    
    # Find TPs in file1 but not in file2
    unique_to_file1 = []
    for key, tp in tps1_keys.items():
        if key not in tps2_keys:
            unique_to_file1.append(tp)
    
    # Print summary
    print(f"Results from: {file1}")
    print(f"  Total true positives: {len(tps1)}")
    print(f"\nComparing to: {file2}")
    print(f"  Total true positives: {len(tps2)}")
    print(f"\nTrue positives in first file but NOT in second: {len(unique_to_file1)}")
    print("="*80)
    
    # Print details
    if unique_to_file1:
        print("\nLost True Positives:")
        for tp in unique_to_file1:
            print(f"\n  File: {tp['file']}")
            print(f"  Sink Line: {tp['sink_line']}")
            print(f"  Vulnerability: {tp.get('vulnerability', 'N/A')}")
            print(f"  Challenges: {', '.join(tp.get('challenges', []))}")
    else:
        print("\nNo true positives were lost!")
    
    # Save to file if requested
    if output_file:
        output = {
            "comparison": {
                "file1": file1,
                "file2": file2,
                "tps_in_file1": len(tps1),
                "tps_in_file2": len(tps2),
                "lost_tps_count": len(unique_to_file1)
            },
            "lost_true_positives": unique_to_file1
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        print(f"\n\nDetailed comparison saved to: {output_file}")
    
    return unique_to_file1

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python compare_results.py <results1.json> <results2.json> [output.json]")
        sys.exit(1)
    
    file1 = sys.argv[1]
    file2 = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    compare_true_positives(file1, file2, output_file)