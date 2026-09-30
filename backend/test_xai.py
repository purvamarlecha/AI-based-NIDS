import os
import joblib
import pandas as pd

from xai_explainer import explain_prediction


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

DATASET_PATH = os.path.join(
    PROJECT_DIR,
    "dataset",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)


# ============================================================
# START
# ============================================================

print("\n==========================================")
print("          AI-NIDS XAI TEST")
print("==========================================\n")


# ============================================================
# CHECK FILES
# ============================================================

for path in [
    MODEL_PATH,
    ENCODER_PATH,
    FEATURES_PATH,
    DATASET_PATH
]:

    if not os.path.exists(path):

        print("ERROR: File not found:")
        print(path)

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
    "Features:",
    len(features)
)

print(
    "Classes:",
    list(label_encoder.classes_)
)


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading DDoS dataset...")

data = pd.read_csv(
    DATASET_PATH
)

data.columns = data.columns.str.strip()

print(
    "Total records:",
    len(data)
)


# ============================================================
# FIND DDOS RECORD
# ============================================================

ddos_data = data[
    data["Label"]
    .astype(str)
    .str.strip()
    .str.upper()
    == "DDOS"
]


print(
    "DDoS records:",
    len(ddos_data)
)


if len(ddos_data) == 0:

    print("\nNo DDoS records found.")

    exit()


# ============================================================
# SELECT ONE RECORD
# ============================================================

sample = ddos_data.iloc[[0]].copy()


# ============================================================
# PREPARE FEATURES
# ============================================================

X = sample.drop(
    columns=["Label"]
)

X = X.select_dtypes(
    include=["number"]
)

X = X.replace(
    [float("inf"), float("-inf")],
    0
)

X = X.fillna(0)


# Add missing model features

for feature in features:

    if feature not in X.columns:

        X[feature] = 0


# Correct feature order

X = X[features]


print(
    "\nPrepared features:",
    len(X.columns)
)


# ============================================================
# PREDICTION
# ============================================================

prediction = model.predict(X)[0]

prediction_name = label_encoder.inverse_transform(
    [prediction]
)[0]


print("\n==========================================")
print("             AI PREDICTION")
print("==========================================")

print(
    "Prediction:",
    prediction_name
)


# ============================================================
# CONFIDENCE
# ============================================================

probabilities = model.predict_proba(X)

confidence = (
    max(probabilities[0])
    * 100
)

print(
    "Confidence:",
    round(confidence, 2),
    "%"
)


# ============================================================
# XAI EXPLANATION
# ============================================================

print("\nGenerating XAI explanation...")

result = explain_prediction(
    model,
    X,
    features,
    label_encoder
)


print("\n==========================================")
print("           XAI EXPLANATION")
print("==========================================")

print(
    "\nDetected activity:",
    result["prediction"]
)


if result["top_features"]:

    print("\nTop contributing features:\n")

    for item in result["top_features"]:

        print(
            f"{item['feature']:<35} "
            f"Impact: {item['impact']:.4f}"
        )

else:

    print(
        "\nNo feature explanation available."
    )

    if "error" in result:

        print(
            "Reason:",
            result["error"]
        )


print("\n==========================================")
print("          XAI TEST COMPLETED")
print("==========================================")