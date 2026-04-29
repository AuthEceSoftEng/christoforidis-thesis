"""
Repository cloning and web scraping utilities.

Provides two main capabilities:
  - clone_vulnerable_repos(): Reads CVE JSON files to clone repositories at
    their pre-patch commit, creating a snapshot of the vulnerable codebase.
  - extract_cwe_codes(): Scrapes OWASP Top 10 web pages to extract CWE codes,
    used to build the evaluation subset of CVEs.
"""

import os
import json
import subprocess
import logging
import requests
from bs4 import BeautifulSoup
import re

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def clone_vulnerable_repos(json_folder: str, output_folder: str):
    """
    Clone repositories at their pre-patch commits for vulnerability evaluation.

    Reads CVE JSON files from the given folder, extracts the repository URL
    and pre-patch commit hash, and clones each repo at that specific commit.
    Skips repositories that have already been cloned.

    Args:
        json_folder: Path to directory containing CVE JSON files.
        output_folder: Path to directory where repos will be cloned.
    """
    # output folder exists
    os.makedirs(output_folder, exist_ok=True)

    # iterate all JSON files
    for filename in os.listdir(json_folder):
        if filename.endswith(".json"):
            json_path = os.path.join(json_folder, filename)
            with open(json_path, "r", encoding="utf-8") as file:
                try:
                    data = json.load(file)
                    repo_url = data["repository"]
                    commit_hash = data["prePatch"]["commit"]

                    # use repo name for folder
                    repo_name = repo_url.rstrip(".git").split("/")[-1]
                    clone_path = os.path.join(output_folder, f"{repo_name}-{commit_hash[:7]}")

                    # skip already cloned
                    if os.path.exists(clone_path):
                        logger.info(f"Repo already cloned: {clone_path}")
                        continue

                    logger.info(f"Cloning {repo_url} at commit {commit_hash}")

                    # Clone and checkout the commit
                    subprocess.run(["git", "clone", repo_url, clone_path], check=True)
                    subprocess.run(["git", "checkout", commit_hash], cwd=clone_path, check=True)

                    logger.info(f"Cloned into {clone_path}")

                except (KeyError, json.JSONDecodeError) as e:
                    logger.error(f"Error processing {filename}: {e}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Git error in {filename}: {e}")

def extract_cwe_codes(url):
    """
    Scrape CWE codes from a given URL (e.g., OWASP Top 10 pages).

    Fetches the page HTML, extracts all text, and finds all occurrences
    of the pattern 'CWE-<number>'.

    Args:
        url: URL of the page to scrape.

    Returns:
        List of unique CWE code strings (e.g., ['CWE-79', 'CWE-89']).
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Request failed: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    text = soup.get_text()

    # find all CWE codes in the format CWE-<number>
    cwe_codes = re.findall(r'CWE-\d+', text)

    return list(set(cwe_codes))  # remove duplicates

if __name__ == "__main__":
    # scrape CWE codes from OWASP Top 10 pages
    urls = [
    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/#list-of-mapped-cwes",
    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/#list-of-mapped-cwes",
    "https://owasp.org/Top10/A03_2021-Injection/#list-of-mapped-cwes",
    "https://owasp.org/Top10/A04_2021-Insecure_Design/#list-of-mapped-cwes",
    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/#list-of-mapped-cwes",
    "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/#list-of-mapped-cwes",
    "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/#list-of-mapped-cwes",
    "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/#list-of-mapped-cwes",
    "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/#list-of-mapped-cwes",
    "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/#list-of-mapped-cwes"
    ]
    for url in urls:
        cwe_codes = extract_cwe_codes(url)
        logger.info(f"Extracted CWE codes: {cwe_codes} from {url}")
    
        file = os.path.join(os.path.dirname(__file__), "..", "evaluation_cves", "cwe_codes_top10.txt")
        with open(file, "a") as f:
            for cwe in cwe_codes:
                f.write(f"{cwe}\n")