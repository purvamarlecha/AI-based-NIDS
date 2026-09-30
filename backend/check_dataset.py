import pandas as pd
import os

dataset_folder = "dataset"

files = [
    f for f in os.listdir(dataset_folder)
    if f.lower().endswith(".csv")
]

print("CSV files found:")
for file in files:
    print("-", file)

if not files:
    print("\nNo CSV files found.")
    exit()

file_path = os.path.join(dataset_folder, files[0])

print("\nReading:", files[0])

data = pd.read_csv(file_path)

print("\nDataset shape:")
print(data.shape)

print("\nColumns:")
for column in data.columns:
    print("-", column)

print("\nFirst 5 rows:")
print(data.head())