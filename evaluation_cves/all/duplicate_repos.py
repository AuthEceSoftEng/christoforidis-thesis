import os
import json
from collections import defaultdict

# Path to the folder containing your JSON files
FOLDER_PATH = r"C:\Projects\thesis\evaluation_cves\all"

def find_duplicate_repos(folder_path):
    repo_map = defaultdict(list)

    # Loop through all JSON files in the folder
    for filename in os.listdir(folder_path):
        if not filename.endswith(".json"):
            continue

        file_path = os.path.join(folder_path, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                repo = data.get("repository")
                if repo:
                    repo_map[repo].append(filename)
        except Exception as e:
            print(f"Error reading {filename}: {e}")

    # Filter to only repos that appear in multiple files
    duplicates = {repo: files for repo, files in repo_map.items() if len(files) > 1}
    return duplicates

if __name__ == "__main__":
    duplicates = find_duplicate_repos(FOLDER_PATH)
    if duplicates:
        print("Repositories appearing in multiple files:\n")
        for repo, files in duplicates.items():
            print(f"{repo}:")
            for f in files:
                print(f"  - {f}")
    else:
        print("No repositories found in multiple files.")
