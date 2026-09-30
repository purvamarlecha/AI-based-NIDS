import pandas as pd
import joblib
import os


# ==========================================
# AI-NIDS MODEL TESTING
# ==========================================

print("\n==========================================")
print("       AI-NIDS MODEL TESTING")
print("==========================================\n")


# ==========================================
# FILE PATHS
# ==========================================

MODEL_PATH = "model/random_forest_model.pkl"
ENCODER_PATH = "model/label_encoder.pkl"
FEATURES_PATH = "model/features.pkl"

# ------------------------------------------
# CHANGE ONLY THIS FILE WHEN NEEDED
# ------------------------------------------

TEST_FILE = (
    "dataset/"
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)


# ==========================================
# TEST SETTINGS
# ==========================================

TEST_SAMPLES = 20


# ==========================================
# CHECK REQUIRED FILES
# ==========================================

print("Checking required files...\n")

required_files = [
    MODEL_PATH,
    ENCODER_PATH,
    FEATURES_PATH,
    TEST_FILE
]

for file_path in required_files:

    if not os.path.exists(file_path):

        print("ERROR: File not found:")
        print(file_path)
        print("\nPlease check the file path.")
        exit()


print("All required files found.")


# ==========================================
# LOAD AI MODEL
# ==========================================

print("\nLoading AI model...")

model = joblib.load(
    MODEL_PATH
)

label_encoder = joblib.load(
    ENCODER_PATH
)

features = joblib.load(
    FEATURES_PATH
)


print("AI model loaded successfully!")

print(
    "Model features:",
    len(features)
)

print(
    "Attack classes:",
    list(label_encoder.classes_)
)


# ==========================================
# LOAD TEST DATASET
# ==========================================

print("\nLoading test dataset...")

data = pd.read_csv(
    TEST_FILE,
    low_memory=False
)

# Clean column names

data.columns = (
    data.columns
    .str.strip()
)


print(
    "Total records:",
    len(data)
)


# ==========================================
# CHECK LABEL COLUMN
# ==========================================

if "Label" not in data.columns:

    print(
        "\nERROR: 'Label' column not found."
    )

    print("\nAvailable columns:")

    for column in data.columns:

        print("-", column)

    exit()


# ==========================================
# CLEAN LABELS
# ==========================================

data["Label"] = (
    data["Label"]
    .astype(str)
    .str.strip()
)


# ==========================================
# SHOW DATASET LABELS
# ==========================================

print("\nLabels found in dataset:")

label_counts = (
    data["Label"]
    .value_counts()
)


for label, count in label_counts.items():

    print(
        f"'{label}' : {count}"
    )


# ==========================================
# FIND ATTACK LABEL
# ==========================================

# Remove BENIGN

attack_labels = data[
    data["Label"].str.upper() != "BENIGN"
]["Label"].unique()


if len(attack_labels) == 0:

    print(
        "\nNo attack records found in this dataset."
    )

    exit()


# ==========================================
# SELECT ATTACK
# ==========================================

# Normally the selected file contains
# one attack type + BENIGN records.

attack_name = attack_labels[0]


print(
    "\nSelected attack:",
    attack_name
)


# ==========================================
# GET ATTACK RECORDS
# ==========================================

attack_data = data[
    data["Label"] == attack_name
].copy()


print(
    f"{attack_name} records found:",
    len(attack_data)
)


if len(attack_data) == 0:

    print(
        "\nNo attack records available."
    )

    exit()


# ==========================================
# CHECK FEATURES
# ==========================================

missing_features = [
    feature
    for feature in features
    if feature not in attack_data.columns
]


if missing_features:

    print(
        "\nERROR: Missing model features:"
    )

    for feature in missing_features:

        print(
            "-",
            feature
        )

    exit()


# ==========================================
# PREPARE FEATURES
# ==========================================

print(
    f"\nPreparing {attack_name} features..."
)


X = attack_data[
    features
].copy()


# ==========================================
# CONVERT FEATURES TO NUMERIC
# ==========================================

for feature in features:

    X[feature] = pd.to_numeric(
        X[feature],
        errors="coerce"
    )


# ==========================================
# CLEAN INFINITE VALUES
# ==========================================

X = X.replace(
    [float("inf"), float("-inf")],
    0
)


# ==========================================
# CLEAN MISSING VALUES
# ==========================================

X = X.fillna(0)


print(
    "Features prepared:",
    len(X.columns)
)


# ==========================================
# SELECT TEST RECORDS
# ==========================================

if len(X) < TEST_SAMPLES:

    TEST_SAMPLES = len(X)


sample = X.iloc[
    :TEST_SAMPLES
]


# ==========================================
# RUN AI PREDICTIONS
# ==========================================

print("\nRunning AI predictions...")


predictions = model.predict(
    sample
)


prediction_labels = (
    label_encoder.inverse_transform(
        predictions
    )
)


# ==========================================
# GET CONFIDENCE
# ==========================================

if hasattr(
    model,
    "predict_proba"
):

    probabilities = (
        model.predict_proba(
            sample
        )
    )

else:

    probabilities = None


# ==========================================
# DISPLAY RESULTS
# ==========================================

print("\n==========================================")
print(
    f"        {attack_name} TEST RESULTS"
)
print("==========================================\n")


for i in range(TEST_SAMPLES):

    if probabilities is not None:

        confidence = (
            max(
                probabilities[i]
            ) * 100
        )

    else:

        confidence = 0


    print(
        f"Record {i + 1:02d} | "
        f"Actual: {attack_name} | "
        f"Prediction: {prediction_labels[i]} | "
        f"Confidence: {confidence:.2f}%"
    )


# ==========================================
# PREDICTION SUMMARY
# ==========================================

print("\n==========================================")
print("             TEST SUMMARY")
print("==========================================\n")


prediction_counts = (
    pd.Series(
        prediction_labels
    )
    .value_counts()
)


for label, count in (
    prediction_counts.items()
):

    percentage = (
        count / TEST_SAMPLES
    ) * 100


    print(
        f"{label:<12}: "
        f"{count} records "
        f"({percentage:.2f}%)"
    )


# ==========================================
# ACCURACY FOR SELECTED ATTACK
# ==========================================

correct_predictions = sum(
    prediction_labels == attack_name
)


test_accuracy = (
    correct_predictions /
    TEST_SAMPLES
) * 100


print("\n==========================================")
print("          ATTACK TEST ACCURACY")
print("==========================================\n")


print(
    f"Correct predictions : "
    f"{correct_predictions}/{TEST_SAMPLES}"
)


print(
    f"Test accuracy       : "
    f"{test_accuracy:.2f}%"
)


# ==========================================
# FINAL STATUS
# ==========================================

print("\n==========================================")
print(
    f"       {attack_name} TEST COMPLETED"
)
print("==========================================")

print(
    f"\nTested {TEST_SAMPLES} "
    f"{attack_name} records."
)

print(
    "\nAI-NIDS model testing completed successfully!"
)