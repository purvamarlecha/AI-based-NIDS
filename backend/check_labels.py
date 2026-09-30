import pandas as pd
import os

dataset_folder = "dataset"

files = [
    f for f in os.listdir(dataset_folder)
    if f.lower().endswith(".csv")
]

if not files:
    print("No CSV files found in dataset folder.")
    exit()

print("CSV files found:")
for file in files:
    print("-", file)

print("\nChecking labels...\n")

for file in files:

    file_path = os.path.join(dataset_folder, file)

    print("=" * 60)
    print("File:", file)

    try:
        data = pd.read_csv(file_path)

        data.columns = data.columns.str.strip()

        if "Label" in data.columns:

            print("\nNumber of records:", len(data))

            print("\nAttack distribution:")
            print(data["Label"].value_counts())

        else:
            print("Label column not found.")

    except Exception as e:
        print("Error reading file:", e)

print("\nDataset analysis completed.")