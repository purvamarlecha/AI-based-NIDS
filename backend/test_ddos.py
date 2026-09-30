import pandas as pd
import joblib
import os
import sqlite3


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_DIR = os.path.dirname(BASE_DIR)

MODEL_PATH = os.path.join(
    PROJECT_DIR,
    "model",
    "random_forest_model.pkl"
)

ENCODER_PATH = os.path.join(
    PROJECT_DIR,
    "model",
    "label_encoder.pkl"
)

FEATURES_PATH = os.path.join(
    PROJECT_DIR,
    "model",
    "features.pkl"
)

DATABASE_PATH = os.path.join(
    PROJECT_DIR,
    "model",
    "attack_history.db"
)

TEST_FILE = os.path.join(
    PROJECT_DIR,
    "dataset",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)


# ============================================================
# START
# ============================================================

print("\n==========================================")
print("       AI-NIDS ATTACK TESTING")
print("==========================================\n")


# ============================================================
# CHECK FILES
# ============================================================

for path in [
    MODEL_PATH,
    ENCODER_PATH,
    FEATURES_PATH,
    TEST_FILE,
    DATABASE_PATH
]:

    if not os.path.exists(path):

        print("ERROR: File not found:")
        print(path)

        input("\nPress Enter to exit...")
        exit()


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading AI model...")

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
    "Attack classes:",
    list(label_encoder.classes_)
)


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading DDoS dataset...")

data = pd.read_csv(
    TEST_FILE
)

data.columns = data.columns.str.strip()

print(
    "Total records:",
    len(data)
)


# ============================================================
# SHOW LABELS
# ============================================================

print("\nLabels found in dataset:")

print(
    data["Label"]
    .value_counts()
)


# ============================================================
# SELECT DDOS RECORDS
# ============================================================

ddos_data = data[
    data["Label"]
    .astype(str)
    .str.strip()
    .str.upper()
    == "DDOS"
].copy()


print(
    "\nDDoS records found:",
    len(ddos_data)
)


if len(ddos_data) == 0:

    print("\nNo DDoS records found.")

    input("\nPress Enter to exit...")

    exit()


# ============================================================
# PREPARE FEATURES
# ============================================================

print("\nPreparing DDoS features...")

X = ddos_data.copy()


# Remove label

if "Label" in X.columns:

    X = X.drop(
        columns=["Label"]
    )


# Keep numeric columns

X = X.select_dtypes(
    include=["number"]
)


# Replace infinity

X = X.replace(
    [float("inf"), float("-inf")],
    0
)


# Replace missing values

X = X.fillna(0)


# ============================================================
# MATCH MODEL FEATURES
# ============================================================

for feature in features:

    if feature not in X.columns:

        X[feature] = 0


X = X[features]


print(
    "Features prepared:",
    len(X.columns)
)


# ============================================================
# TEST FIRST 20 RECORDS
# ============================================================

number_of_records = min(
    20,
    len(X)
)

X_test = X.iloc[
    :number_of_records
]


print("\nRunning AI predictions...\n")


predictions = model.predict(
    X_test
)

probabilities = model.predict_proba(
    X_test
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

connection = sqlite3.connect(
    DATABASE_PATH
)

cursor = connection.cursor()


# ============================================================
# RESULTS
# ============================================================

print("==========================================")
print("           DDoS TEST RESULTS")
print("==========================================\n")


saved_count = 0


for index in range(
    number_of_records
):

    prediction_number = predictions[index]

    prediction_label = (
        label_encoder
        .inverse_transform(
            [prediction_number]
        )[0]
    )


    confidence = (
        max(
            probabilities[index]
        ) * 100
    )


    print(
        f"Record {index + 1:02d} | "
        f"Actual: DDoS | "
        f"Prediction: {prediction_label} | "
        f"Confidence: {confidence:.2f}%"
    )


    # ========================================================
    # SAVE ONLY IF MODEL DETECTS AN ATTACK
    # ========================================================

    if prediction_label.upper() != "BENIGN":

        if prediction_label.upper() == "DDOS":

            risk_score = 95

            severity = "CRITICAL"

            recommendation = (
                "Block the suspicious source IP "
                "and investigate the traffic."
            )

        elif prediction_label.upper() == "PORTSCAN":

            risk_score = 75

            severity = "HIGH"

            recommendation = (
                "Monitor the source IP and "
                "restrict suspicious scanning activity."
            )

        else:

            risk_score = 50

            severity = "MEDIUM"

            recommendation = (
                "Investigate the suspicious network activity."
            )


        # ----------------------------------------------------
        # Dataset records do not contain live source/destination
        # information in the same format as our live capture.
        # Use a clearly marked test address.
        # ----------------------------------------------------

        source_ip = "DATASET-TEST"

        destination_ip = "DATASET-TEST"

        source_port = 0

        destination_port = 0

        protocol = "TCP"


        cursor.execute(
            """
            INSERT INTO attack_history
            (
                timestamp,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                attack_type,
                confidence,
                risk_score,
                severity,
                recommendation
            )
            VALUES
            (
                datetime('now'),
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
            """,
            (
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                prediction_label,
                confidence,
                risk_score,
                severity,
                recommendation
            )
        )


        saved_count += 1


# ============================================================
# CLOSE DATABASE
# ============================================================

connection.commit()

connection.close()


# ============================================================
# SUMMARY
# ============================================================

print("\n==========================================")
print("             TEST SUMMARY")
print("==========================================")

print(
    "\nRecords tested:",
    number_of_records
)

print(
    "Attack records saved:",
    saved_count
)


print("\n==========================================")
print("       DDoS TEST COMPLETED")
print("==========================================")

print(
    "\nAI-NIDS testing completed successfully!"
)

input("\nPress Enter to exit...")