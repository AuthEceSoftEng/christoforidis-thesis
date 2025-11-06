import os
import pandas as pd

# Path to the parent directory containing all the folders
parent_dir = r"C:\Projects\thesis\output\mini_evaluation4"

# Walk through all subdirectories
for root, dirs, files in os.walk(parent_dir):
    # Ignore any 'problems' subfolders
    dirs[:] = [d for d in dirs if d.lower() != 'problems']
    # Safety: skip if current root itself is a 'problems' folder
    if os.path.basename(root).lower() == 'problems':
        continue
    
    # Filter only CSV files, skipping any that start with 'combined' or 'deduplicated'
    csv_files = [
        f for f in files
        if f.lower().endswith('.csv') and not f.lower().startswith(('combined', 'deduplicated'))
    ]

    if not csv_files:
        continue  # Skip folders without CSVs

    combined_data = []
    print(f"📁 Processing folder: {root}")

    # Read and append each CSV file
    for csv_file in csv_files:
        file_path = os.path.join(root, csv_file)
        try:
            df = pd.read_csv(file_path, header=None)
            combined_data.append(df)
        except Exception as e:
            print(f"⚠️ Could not read {file_path}: {e}")

    if combined_data:
        # Step 1: Combine all CSVs
        combined_df = pd.concat(combined_data, ignore_index=True)
        combined_path = os.path.join(root, "combined.csv")
        combined_df.to_csv(combined_path, index=False, header=False)
        print(f"✅ Combined CSV saved to: {combined_path}")

        # Step 2: Deduplicate based on columns 4–8
        deduped_df = combined_df.drop_duplicates(subset=[4, 5, 6, 7, 8])
        deduped_path = os.path.join(root, "deduplicated.csv")
        deduped_df.to_csv(deduped_path, index=False, header=False)
        print(f"✅ Deduplicated CSV saved to: {deduped_path}")
