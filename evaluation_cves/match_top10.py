import os
import json
import logging
import random
import shutil

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def match_top10(cves_folder, top10_file):
    with open(top10_file, 'r') as f:
        top10_cwes = set(line.strip() for line in f if line.strip())
    
    matched = []
    
    for filename in os.listdir(cves_folder):
        if filename.endswith('.json'):
            cve_path = os.path.join(cves_folder, filename)
            with open(cve_path, 'r') as cve_file:
                try:
                    cve_data = json.load(cve_file)
                    cwe_codes = set(cve_data.get('CWEs', []))
                    
                    # Check if any CWE in the CVE matches the Top 10 list
                    if cwe_codes.intersection(top10_cwes):
                        logger.info(f"{filename} matches Top 10 CWE: {cwe_codes.intersection(top10_cwes)}")
                        matched.append([filename, cwe_codes.intersection(top10_cwes)])
                except json.JSONDecodeError as e:
                    logger.error(f"Error decoding JSON from {filename}: {e}")
                except KeyError as e:
                    logger.error(f"Missing expected key in {filename}: {e}")
    
    return matched, len(matched)

if __name__ == "__main__":
    cves_folder = os.path.join(os.path.dirname(__file__), "all")
    top10_file = os.path.join(os.path.dirname(__file__), "cwe_codes_top10.txt")
    
    matched_cves, count = match_top10(cves_folder, top10_file)
    
    seed = 44 # set a fixed seed for reproducibility
    random.seed(seed)

    random_numbers = [random.randint(1, count) for _ in range(50)]
    random_cves = []
    cwes = set()
    
    for i in random_numbers:
        if len(random_cves) == 10:
            break
        cve = matched_cves[i]
        if not cve[1].issubset(cwes):
            random_cves.append(cve)
            cwes.update(cve[1])

    cves_names = [cve[0] for cve in random_cves]
    src = os.path.join(os.path.dirname(__file__), "all")
    dst = os.path.join(os.path.dirname(__file__), 'mini_evaluation')
    os.makedirs(dst, exist_ok=True)

    for cve_name in cves_names:
        src_path = os.path.join(src, cve_name)
        if os.path.exists(src_path):
            shutil.copy(src_path, dst)
            logger.info(f"Copied {cve_name} to {dst}")
        else:
            logger.warning(f"Source file {src_path} does not exist.")