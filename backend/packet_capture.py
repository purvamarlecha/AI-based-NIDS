from scapy.all import sniff, IP, TCP, UDP
import joblib
import pandas as pd
import os
import sys
import time
import sqlite3

from flow_features import create_flow_key, calculate_flow_features
from security_analysis import analyze_threat
from xai_explanation import explain_prediction
from attack_logger import log_attack


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_DIR = os.path.dirname(
    BASE_DIR
)


# ============================================================
# AI MODEL PATHS
# ============================================================

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


# ============================================================
# DATABASE PATH
# ============================================================

DATABASE_PATH = os.path.join(
    PROJECT_DIR,
    "model",
    "attack_history.db"
)


# ============================================================
# HEADER
# ============================================================

print("\n==========================================")
print("        AI-NIDS LIVE FLOW MONITOR")
print("==========================================\n")


# ============================================================
# CHECK MODEL FILES
# ============================================================

if not os.path.exists(MODEL_PATH):

    print("ERROR: AI model not found.")
    print(MODEL_PATH)
    print("\nPlease train the model first.")

    sys.exit()


if not os.path.exists(ENCODER_PATH):

    print("ERROR: Label encoder not found.")
    print(ENCODER_PATH)

    sys.exit()


if not os.path.exists(FEATURES_PATH):

    print("ERROR: Feature file not found.")
    print(FEATURES_PATH)

    sys.exit()


# ============================================================
# CHECK DATABASE
# ============================================================

if not os.path.exists(DATABASE_PATH):

    print("ERROR: Attack history database not found.")
    print(DATABASE_PATH)

    sys.exit()


# ============================================================
# LOAD AI MODEL
# ============================================================

try:

    model = joblib.load(
        MODEL_PATH
    )

    label_encoder = joblib.load(
        ENCODER_PATH
    )

    features = joblib.load(
        FEATURES_PATH
    )

except Exception as error:

    print(
        "ERROR loading AI model:",
        error
    )

    sys.exit()


print("AI model loaded successfully!")

print(
    "Features:",
    len(features)
)

print(
    "Attack classes:",
    list(label_encoder.classes_)
)


# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}

FLOW_TIMEOUT = 5


# ============================================================
# CREATE NEW FLOW
# ============================================================

def create_new_flow(packet):

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    src_port = 0
    dst_port = 0

    protocol = packet[IP].proto

    if packet.haslayer(TCP):

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return {

        "packets": [],

        "start_time": time.time(),

        "source_ip": src_ip,

        "destination_ip": dst_ip,

        "source_port": src_port,

        "destination_port": dst_port,

        "protocol": protocol

    }


# ============================================================
# CONVERT PROTOCOL NUMBER TO NAME
# ============================================================

def get_protocol_name(protocol):

    if protocol == 6:

        return "TCP"

    elif protocol == 17:

        return "UDP"

    elif protocol == 1:

        return "ICMP"

    return str(protocol)


# ============================================================
# SAVE FLOW FEATURES TO DATABASE
# ============================================================

def save_flow_features(
    flow,
    attack_name,
    feature_data
):

    try:

        connection = sqlite3.connect(
            DATABASE_PATH
        )

        cursor = connection.cursor()


        # ----------------------------------------------------
        # Find latest matching attack record
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT id
            FROM attack_history
            WHERE source_ip = ?
            AND destination_ip = ?
            AND source_port = ?
            AND destination_port = ?
            AND attack_type = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                flow["source_ip"],
                flow["destination_ip"],
                flow["source_port"],
                flow["destination_port"],
                attack_name
            )
        )


        record = cursor.fetchone()


        if record is None:

            print(
                "\nFeature storage skipped:"
                " attack record not found."
            )

            connection.close()

            return


        attack_id = record[0]


        # ----------------------------------------------------
        # Save all 12 flow features
        # ----------------------------------------------------

        cursor.execute(
            """
            UPDATE attack_history

            SET

                flow_duration = ?,

                total_fwd_packets = ?,

                total_backward_packets = ?,

                total_length_fwd_packets = ?,

                total_length_bwd_packets = ?,

                flow_bytes_per_second = ?,

                flow_packets_per_second = ?,

                packet_length_mean = ?,

                packet_length_std = ?,

                fwd_packet_length_mean = ?,

                bwd_packet_length_mean = ?

            WHERE id = ?
            """,

            (

                float(
                    feature_data.get(
                        "Flow Duration",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Total Fwd Packets",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Total Backward Packets",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Total Length of Fwd Packets",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Total Length of Bwd Packets",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Flow Bytes/s",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Flow Packets/s",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Packet Length Mean",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Packet Length Std",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Fwd Packet Length Mean",
                        0
                    )
                ),

                float(
                    feature_data.get(
                        "Bwd Packet Length Mean",
                        0
                    )
                ),

                attack_id

            )
        )


        connection.commit()

        connection.close()


        print(
            "Flow features saved to database."
        )


    except Exception as error:

        print(
            "\nFlow feature database error:",
            error
        )


# ============================================================
# ANALYZE FLOW
# ============================================================

def analyze_flow(flow):

    # ========================================================
    # CALCULATE FEATURES
    # ========================================================

    feature_data = calculate_flow_features(
        flow
    )


    if feature_data is None:

        return


    # ========================================================
    # CONVERT TO DATAFRAME
    # ========================================================

    data = pd.DataFrame(
        [feature_data]
    )


    # ========================================================
    # MATCH MODEL FEATURES
    # ========================================================

    for feature in features:

        if feature not in data.columns:

            data[feature] = 0


    data = data[
        features
    ]


    # ========================================================
    # CLEAN DATA
    # ========================================================

    data = data.replace(
        [
            float("inf"),
            float("-inf")
        ],
        0
    )

    data = data.fillna(0)


    # ========================================================
    # AI PREDICTION
    # ========================================================

    try:

        prediction = model.predict(
            data
        )

        attack_name = (
            label_encoder
            .inverse_transform(
                prediction
            )[0]
        )

    except Exception as error:

        print(
            "\nAI prediction error:",
            error
        )

        return


    # ========================================================
    # CONFIDENCE
    # ========================================================

    confidence = 0.0

    probabilities = None


    if hasattr(
        model,
        "predict_proba"
    ):

        try:

            probabilities = (
                model.predict_proba(
                    data
                )
            )

            confidence = (
                max(
                    probabilities[0]
                ) * 100
            )

        except Exception as error:

            print(
                "Confidence calculation error:",
                error
            )

            confidence = 0.0


    # ========================================================
    # FLOW INFORMATION
    # ========================================================

    print("\n==========================================")
    print("             FLOW ANALYSIS")
    print("==========================================")

    print(
        "Source IP       :",
        flow["source_ip"]
    )

    print(
        "Destination IP  :",
        flow["destination_ip"]
    )

    print(
        "Source Port     :",
        flow["source_port"]
    )

    print(
        "Destination Port:",
        flow["destination_port"]
    )

    print(
        "Protocol        :",
        get_protocol_name(
            flow["protocol"]
        )
    )

    print(
        "Packets         :",
        len(flow["packets"])
    )

    print(
        "AI Prediction   :",
        attack_name
    )

    print(
        "Confidence      :",
        round(
            confidence,
            2
        ),
        "%"
    )


    # ========================================================
    # SECURITY ANALYSIS
    # ========================================================

    try:

        security = analyze_threat(

            attack_name,

            confidence,

            len(
                flow["packets"]
            )

        )

    except Exception as error:

        print(
            "\nSecurity analysis error:",
            error
        )

        security = {

            "risk_score": 0,

            "severity": "LOW",

            "recommendation":
                "Continue monitoring network activity."

        }


    risk_score = security.get(
        "risk_score",
        0
    )

    severity = security.get(
        "severity",
        "LOW"
    )

    recommendation = security.get(
        "recommendation",
        "Continue monitoring network activity."
    )


    # ========================================================
    # SECURITY ANALYSIS DISPLAY
    # ========================================================

    print("\n------------------------------------------")
    print("          SECURITY ANALYSIS")
    print("------------------------------------------")

    print(
        "Risk Score      :",
        risk_score,
        "/ 100"
    )

    print(
        "Threat Severity :",
        severity
    )

    print(
        "Recommendation  :",
        recommendation
    )


    # ========================================================
    # SAVE ATTACK TO HISTORY
    # ========================================================

    if attack_name.upper() != "BENIGN":

        try:

            log_attack(

                source_ip=flow["source_ip"],

                destination_ip=
                    flow["destination_ip"],

                source_port=
                    flow["source_port"],

                destination_port=
                    flow["destination_port"],

                protocol=
                    get_protocol_name(
                        flow["protocol"]
                    ),

                attack_type=
                    attack_name,

                confidence=
                    confidence,

                risk_score=
                    risk_score,

                severity=
                    severity,

                recommendation=
                    recommendation

            )


            print(
                "\nAttack history updated successfully."
            )


            # ------------------------------------------------
            # SAVE ACTUAL FLOW FEATURES
            # ------------------------------------------------

            save_flow_features(

                flow,

                attack_name,

                feature_data

            )


        except Exception as error:

            print(
                "\nAttack logging error:",
                error
            )


    # ========================================================
    # XAI EXPLANATION
    # ========================================================

    print("\n------------------------------------------")
    print("        EXPLAINABLE AI ANALYSIS")
    print("------------------------------------------")


    try:

        explanation = explain_prediction(

            model,

            data,

            attack_name,

            confidence

        )


        if explanation:

            print(
                explanation
            )

        else:

            print(
                "XAI explanation unavailable."
            )


    except Exception as error:

        print(
            "XAI explanation unavailable:",
            error
        )


    # ========================================================
    # SECURITY ALERT
    # ========================================================

    if attack_name.upper() != "BENIGN":

        print("\n🚨 SECURITY ALERT 🚨")

        print(
            "Threat detected:",
            attack_name
        )

        print(
            "Source:",
            flow["source_ip"]
        )

        print(
            "Destination:",
            flow["destination_ip"]
        )

        print(
            "Severity:",
            severity
        )

        print(
            "Risk Score:",
            risk_score,
            "/ 100"
        )

        print(
            "Confidence:",
            round(
                confidence,
                2
            ),
            "%"
        )

        print(
            "Action:",
            recommendation
        )

    else:

        print(
            "\nStatus          : Normal traffic"
        )


# ============================================================
# PACKET PROCESSOR
# ============================================================

def process_packet(packet):

    # --------------------------------------------------------
    # Only IPv4 packets
    # --------------------------------------------------------

    if not packet.haslayer(IP):

        return


    # --------------------------------------------------------
    # Create flow key
    # --------------------------------------------------------

    flow_key = create_flow_key(
        packet
    )


    if flow_key is None:

        return


    current_time = time.time()


    # --------------------------------------------------------
    # Create new flow
    # --------------------------------------------------------

    if flow_key not in flows:

        flows[flow_key] = (
            create_new_flow(
                packet
            )
        )


    flow = flows[
        flow_key
    ]


    # --------------------------------------------------------
    # Add packet
    # --------------------------------------------------------

    flow["packets"].append(
        packet
    )


    # --------------------------------------------------------
    # Check timeout
    # --------------------------------------------------------

    if (
        current_time -
        flow["start_time"]
        >= FLOW_TIMEOUT
    ):

        try:

            analyze_flow(
                flow
            )

        except Exception as error:

            print(
                "\nFlow analysis error:",
                error
            )

        finally:

            if flow_key in flows:

                del flows[
                    flow_key
                ]


# ============================================================
# START LIVE CAPTURE
# ============================================================

print(
    "\nStarting live network monitoring..."
)

print(
    "Flow timeout:",
    FLOW_TIMEOUT,
    "seconds"
)

print(
    "\nGenerate normal traffic using:"
)

print(
    " - Web browsing"
)

print(
    " - ping -4 google.com"
)

print(
    "\nPress CTRL+C to stop.\n"
)


# ============================================================
# START SCAPY
# ============================================================

try:

    sniff(

        prn=process_packet,

        store=False

    )


except PermissionError:

    print(
        "\nERROR: Permission denied."
    )

    print(
        "Run Command Prompt or PowerShell as Administrator."
    )


except KeyboardInterrupt:

    print(
        "\n\nMonitoring stopped."
    )

    print(
        "\nAnalyzing remaining flows..."
    )


    for flow in list(
        flows.values()
    ):

        try:

            analyze_flow(
                flow
            )

        except Exception as error:

            print(
                "Flow analysis error:",
                error
            )


    flows.clear()


    print(
        "\n=========================================="
    )

    print(
        "          AI-NIDS STOPPED"
    )

    print(
        "=========================================="
    )


except Exception as error:

    print(
        "\nPacket capture error:",
        error
    )