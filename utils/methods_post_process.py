import semver
import re
import subprocess
import json
import logging
import pandas as pd

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def deduplicate_methods(csv_path: str, output_path: str = None) -> pd.DataFrame:
    """
    Deduplicate methods dataframe based on packageName, version, and methodName.
    
    Args:
        csv_path (str): Path to the input CSV file.
        output_path (str, optional): Path to save the deduplicated CSV file.

    Returns:
        pd.DataFrame: Deduplicated DataFrame.
    """
    try:
        # read csv file
        df = df = pd.read_csv(csv_path, header = 0)

        # drop duplicates
        unique_df = df.drop_duplicates(["packageName", "version", "methodName"])

        # sort for readability
        unique_df = unique_df.sort_values(by=["packageName", "methodName"])

        # Save to CSV if output path is provided
        if output_path:
            unique_df.to_csv(output_path, index=False)
            logger.info(f"Deduplicated methods saved to {output_path}")
        
        return unique_df
    
    except Exception as e:
        logger.error(f"Error deduplicating methods: {e}")
        raise

def methods_to_json(df: pd.DataFrame, output_path: str = None) -> list:
    """
    Convert methods DataFrame to JSON format.
    
    Args:
        df (pd.DataFrame): DataFrame containing methods
        output_path (str, optional): Path to save the JSON file.
        
    Returns:
        list: list of method objects
    """

    methods = []

    for (package_name, version), group in df.groupby(["packageName", "version"]):
        package = {
            "package": package_name,
            "version": version,
            "methods": group['methodName'].tolist()
        }
        methods.append(package)

    # Save to JSON if output path is provided
    if output_path:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(methods, f, indent=2, ensure_ascii=False)
            logger.info(f"Methods saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving methods to JSON: {e}")

    return methods

def get_npm_advisories():
    """
    Fetch npm advisories from GitHub API.
    
    Returns:
        list: List of npm advisories.
    """
    try:
        command = [
            "gh", "api", "/advisories?ecosystem=npm",
            "--header", "Accept: application/vnd.github+json",
            "--paginate"
        ]
        
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')
        
        if result.returncode != 0:
            logger.error(f"Error fetching npm advisories: {result.stderr}")
            return []
        
        advisories = json.loads(result.stdout)
        return advisories
    
    except Exception as e:
        logger.error(f"Error fetching npm advisories: {e}")
        return []

def compare_with_advisories(methods_data, output_path=None):
    """
    Compare packages from the codebase with GitHub Security Advisories to identify vulnerabilities.
    
    Args:
        methods_data (list): List of package objects from codeabse
        output_path (str, optional): Path to save the vulnerabilities JSON file
        
    Returns:
        list: List of vulnerable packages with advisory details
    """
    # advisories_data (list): List of advisories from GitHub APIs
    advisories_data=get_npm_advisories()
    
    vulnerable_packages = []
    
    # Process each package in our codebase
    for package_info in methods_data:
        package_name = package_info["package"]
        package_version = package_info["version"]
        
        # Check each advisory for vulnerabilities in this package
        for advisory in advisories_data:
            # Skip if the advisory doesn't have vulnerabilities data
            if "vulnerabilities" not in advisory:
                continue
                
            for vulnerability in advisory["vulnerabilities"]:
                # Skip if the package name doesn't match
                if vulnerability.get("package", {}).get("name") != package_name:
                    continue
                
                # Get vulnerability version information
                vulnerable_range = vulnerability.get("vulnerable_version_range", "")
                patched_version = vulnerability.get("first_patched_version", {})
                
                # Check if our version is vulnerable
                if is_version_vulnerable(package_version, vulnerable_range, patched_version):
                    # Create vulnerability entry with detailed information
                    vuln_entry = {
                        "package": package_name,
                        "version": package_version,
                        "vulnerable_range": vulnerable_range,
                        "patched_version": patched_version,
                        "detected_package_methods": package_info["methods"],
                        "vulnerable_functions": vulnerability.get("vulnerable_functions", []),
                        "advisory": {
                            "summary": advisory.get("summary"),
                            "description": advisory.get("description"),
                            "severity": advisory.get("severity"),
                            "cwes": [
                                {
                                    "cwe_id": cwe.get("cwe_id"),
                                    "name": cwe.get("name")
                                } 
                                for cwe in advisory.get("cwes", [])
                            ]
                        }
                    }
                    vulnerable_packages.append(vuln_entry)
    
    # Save to JSON if output path is provided
    if output_path and vulnerable_packages:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(vulnerable_packages, f, indent=2, ensure_ascii=False)
            logger.info(f"Vulnerable packages saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving vulnerable packages to JSON: {e}")
    
    return vulnerable_packages

def is_version_vulnerable(package_version, vulnerable_range, patched_version):
    """
    Determine if a package version is vulnerable based on the vulnerability range.
    
    Args:
        package_version (str): Version of the package in the codebase
        vulnerable_range (str): Range of vulnerable versions (e.g., ">= 1.10.0, <= 2.0.3")
        patched_version (dict/str): First patched version information
        
    Returns:
        bool: True if the version is vulnerable, False otherwise
    """
    try:
        # If version is unknown, conservatively treat it as vulnerable
        if package_version == "unknown":
            logger.warning(f"Package with unknown version detected. Conservatively marking as vulnerable.")
            return True
        
        # Clean version strings
        package_version = clean_version(package_version)
        
        # Handle patched version from different formats
        if isinstance(patched_version, dict) and "version" in patched_version:
            patched_version = patched_version["version"]
        elif isinstance(patched_version, str):
            patched_version = clean_version(patched_version)
        else:
            patched_version = None
            
        # Parse the vulnerable range
        # Example: ">= 1.10.0, <= 2.0.3"
        if not vulnerable_range:
            return False
            
        # Split into individual conditions
        conditions = [c.strip() for c in vulnerable_range.split(",")]
        
        # Check each condition
        for condition in conditions:
            # Extract operator and version
            match = re.match(r"([<>=!]+)\s*(.*)", condition)
            if not match:
                continue
                
            operator, version = match.groups()
            version = clean_version(version)
            
            # Compare versions based on operator
            if operator == "==" and semver.compare(package_version, version) == 0:
                return True
            elif operator == ">=" and semver.compare(package_version, version) >= 0:
                continue  # Potentially vulnerable, check other conditions
            elif operator == "<=" and semver.compare(package_version, version) <= 0:
                continue  # Potentially vulnerable, check other conditions
            elif operator == ">" and semver.compare(package_version, version) > 0:
                continue  # Potentially vulnerable, check other conditions
            elif operator == "<" and semver.compare(package_version, version) < 0:
                continue  # Potentially vulnerable, check other conditions
            elif operator == "!=" and semver.compare(package_version, version) != 0:
                continue  # Potentially vulnerable, check other conditions
            else:
                return False  # This condition doesn't match, so not vulnerable
        
        # If we reached here, all conditions matched
        
        # Final check: if patched version exists, make sure our version is not the patched version or newer
        if patched_version and semver.compare(package_version, patched_version) >= 0:
            return False
            
        return True
    except Exception as e:
        logger.warning(f"Error checking version vulnerability: {e}")
        # If we can't determine, assume not vulnerable to avoid false positives
        return False

def clean_version(version):
    """
    Clean a version string to make it semver compatible.
    
    Args:
        version (str): Version string to clean
        
    Returns:
        str: Cleaned version string
    """
    # Remove leading 'v' if present
    if version and isinstance(version, str) and version.startswith('v'):
        version = version[1:]
    
    # Ensure it has at least major.minor.patch
    parts = (version or "").split('.')
    while len(parts) < 3:
        parts.append('0')
    
    # Join back together
    return '.'.join(parts)