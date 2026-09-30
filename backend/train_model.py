import pandas as pd
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report


# ==========================================
# CONFIGURATION
# ==========================================

DATASET_FOLDER = "dataset"

SELECTED_FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv"
]

SAMPLES_PER_FILE = 30000


# ==========================================
# FEATURES USED BY LIVE PACKET CAPTURE
# ==========================================

SELECTED_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean"
]


# ==========================================
# START
# ==========================================

print("\n==========================================")
print("       AI-NIDS MODEL TRAINING")
print("==========================================\n")


# ==========================================
# LOAD DATASETS
# ==========================================

dataframes = []


for filename in SELECTED_FILES:

    file_path = os.path.join(
        DATASET_FOLDER,
        filename
    )

    if not os.path.exists(file_path):

        print("WARNING: File not found:")
        print(file_path)
        continue


    print("Loading:", filename)

    try:

        df = pd.read_csv(
            file_path,
            low_memory=False
        )

    except Exception as error:

        print(
            "Error loading",
            filename
        )

        print(error)

        continue


    # --------------------------------------
    # Clean column names
    # --------------------------------------

    df.columns = (
        df.columns
        .str.strip()
    )


    # --------------------------------------
    # Check Label column
    # --------------------------------------

    if "Label" not in df.columns:

        print(
            "WARNING: Label column missing in",
            filename
        )

        continue


    # --------------------------------------
    # Clean labels
    # --------------------------------------

    df["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
    )


    # --------------------------------------
    # Sample records
    # --------------------------------------

    if len(df) > SAMPLES_PER_FILE:

        df = df.sample(
            n=SAMPLES_PER_FILE,
            random_state=42
        )


    print(
        "Records loaded:",
        len(df)
    )


    dataframes.append(df)


# ==========================================
# CHECK DATA
# ==========================================

if not dataframes:

    print("\nERROR: No dataset files were loaded.")
    exit()


# ==========================================
# COMBINE DATASETS
# ==========================================

data = pd.concat(
    dataframes,
    ignore_index=True
)


print("\n==========================================")
print("             DATASET SUMMARY")
print("==========================================")

print(
    "Total records:",
    len(data)
)


# ==========================================
# REMOVE INVALID LABELS
# ==========================================

data = data[
    data["Label"].notna()
]


data = data[
    data["Label"] != ""
]


# ==========================================
# REMOVE DUPLICATE RECORDS
# ==========================================

before_duplicates = len(data)

data = data.drop_duplicates()

after_duplicates = len(data)


print(
    "Duplicate records removed:",
    before_duplicates - after_duplicates
)


# ==========================================
# CHECK REQUIRED FEATURES
# ==========================================

missing_features = [
    feature
    for feature in SELECTED_FEATURES
    if feature not in data.columns
]


if missing_features:

    print("\nERROR: Missing features:")

    for feature in missing_features:

        print(
            "-",
            feature
        )

    print(
        "\nTraining stopped because required features are missing."
    )

    exit()


# ==========================================
# SELECT FEATURES
# ==========================================

X = data[
    SELECTED_FEATURES
].copy()


y = data[
    "Label"
].copy()


# ==========================================
# CONVERT FEATURES TO NUMERIC
# ==========================================

for feature in SELECTED_FEATURES:

    X[feature] = pd.to_numeric(
        X[feature],
        errors="coerce"
    )


# ==========================================
# HANDLE INFINITE VALUES
# ==========================================

X = X.replace(
    [float("inf"), float("-inf")],
    0
)


# ==========================================
# HANDLE MISSING VALUES
# ==========================================

X = X.fillna(0)


# ==========================================
# DISPLAY FEATURES
# ==========================================

print("\nFeatures being used:")

for feature in SELECTED_FEATURES:

    print(
        "-",
        feature
    )


# ==========================================
# DISPLAY ATTACK CLASSES
# ==========================================

print("\nAttack classes before encoding:")

class_counts = y.value_counts()


for label, count in class_counts.items():

    print(
        f"{label}: {count}"
    )


# ==========================================
# ENCODE LABELS
# ==========================================

label_encoder = LabelEncoder()

y_encoded = (
    label_encoder
    .fit_transform(y)
)


print("\nEncoded attack classes:")

for number, label in enumerate(
    label_encoder.classes_
):

    print(
        number,
        "=",
        label
    )


# ==========================================
# CHECK NUMBER OF CLASSES
# ==========================================

if len(
    label_encoder.classes_
) < 2:

    print(
        "\nERROR: At least two attack classes are required."
    )

    exit()


# ==========================================
# SPLIT DATA
# ==========================================

print("\nSplitting dataset...")


X_train, X_test, y_train, y_test = (
    train_test_split(
        X,
        y_encoded,
        test_size=0.20,
        random_state=42,
        stratify=y_encoded
    )
)


print(
    "Training records:",
    len(X_train)
)

print(
    "Testing records:",
    len(X_test)
)


# ==========================================
# TRAIN RANDOM FOREST
# ==========================================

print("\n==========================================")
print("        TRAINING RANDOM FOREST")
print("==========================================\n")


model = RandomForestClassifier(

    n_estimators=100,

    random_state=42,

    n_jobs=-1,

    class_weight="balanced",

    max_features="sqrt"
)


model.fit(
    X_train,
    y_train
)


# ==========================================
# PREDICTION
# ==========================================

print("\nTesting model...")


predictions = model.predict(
    X_test
)


# ==========================================
# ACCURACY
# ==========================================

accuracy = accuracy_score(
    y_test,
    predictions
)


# ==========================================
# RESULTS
# ==========================================

print("\n==========================================")
print("       MODEL TRAINING COMPLETE")
print("==========================================")

print(
    "\nAccuracy:",
    round(
        accuracy * 100,
        2
    ),
    "%"
)


# ==========================================
# CLASSIFICATION REPORT
# ==========================================

print(
    "\nClassification Report:\n"
)


print(
    classification_report(
        y_test,
        predictions,
        target_names=label_encoder.classes_,
        zero_division=0
    )
)


# ==========================================
# MODEL DIRECTORY
# ==========================================

os.makedirs(
    "model",
    exist_ok=True
)


# ==========================================
# SAVE MODEL
# ==========================================

MODEL_PATH = (
    "model/"
    "random_forest_model.pkl"
)

ENCODER_PATH = (
    "model/"
    "label_encoder.pkl"
)

FEATURES_PATH = (
    "model/"
    "features.pkl"
)


joblib.dump(
    model,
    MODEL_PATH
)


joblib.dump(
    label_encoder,
    ENCODER_PATH
)


joblib.dump(
    SELECTED_FEATURES,
    FEATURES_PATH
)


# ==========================================
# SAVE TRAINING INFORMATION
# ==========================================

training_info = {

    "accuracy": accuracy,

    "total_records": len(data),

    "training_records": len(X_train),

    "testing_records": len(X_test),

    "features": SELECTED_FEATURES,

    "classes": list(
        label_encoder.classes_
    )
}


joblib.dump(
    training_info,
    "model/training_info.pkl"
)


# ==========================================
# COMPLETION
# ==========================================

print("\n==========================================")
print("          MODEL SAVED SUCCESSFULLY")
print("==========================================")

print("\nFiles created:")

print(
    "- model/random_forest_model.pkl"
)

print(
    "- model/label_encoder.pkl"
)

print(
    "- model/features.pkl"
)

print(
    "- model/training_info.pkl"
)

print("\nAI-NIDS training completed successfully!")