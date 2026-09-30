import os
import time
import joblib
import numpy as np
import pandas as pd

from scapy.all import sniff, IP, IPv6, TCP, UDP

from database import log_attack


# ============================================================
# AI-NIDS LIVE DETECTION
# ============================================================

print("==========================================")
print("       AI-NIDS LIVE AI DETECTION")
print("==========================================")


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

MODEL_DIR = os.path.join(PROJECT_DIR, "model")

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "random_forest_model.pkl"
)

ENCODER_PATH = os.path.join(
    MODEL_DIR,
    "label_encoder.pkl"
)

FEATURES_PATH = os.path.join(
    MODEL_DIR,
    "features.pkl"
)


# ============================================================
# SETTINGS
# ============================================================

PACKET_COUNT = 50
CAPTURE_TIMEOUT = 10


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading AI model...")

try:

    model = joblib.load(MODEL_PATH)

    label_encoder = joblib.load(
        ENCODER_PATH
    )

    features = joblib.load(
        FEATURES_PATH
    )

except Exception as error:

    print("\nERROR: Could not load AI model.")
    print(error)

    raise SystemExit


print("AI model loaded successfully!")
print("Features:", len(features))
print(
    "Classes:",
    list(label_encoder.classes_)
)


# ============================================================
# GET IP INFORMATION
# ============================================================

def get_ip_addresses(packet):

    if IP in packet:

        return (
            packet[IP].src,
            packet[IP].dst
        )

    if IPv6 in packet:

        return (
            packet[IPv6].src,
            packet[IPv6].dst
        )

    return None, None


# ============================================================
# GET PORT INFORMATION
# ============================================================

def get_ports(packet):

    if TCP in packet:

        return (
            int(packet[TCP].sport),
            int(packet[TCP].dport),
            "TCP"
        )

    if UDP in packet:

        return (
            int(packet[UDP].sport),
            int(packet[UDP].dport),
            "UDP"
        )

    return 0, 0, "OTHER"


# ============================================================
# EXTRACT FLOW FEATURES
# ============================================================

def extract_flow_features(packets):

    forward_lengths = []
    backward_lengths = []

    source_ip = None
    destination_ip = None

    source_port = 0
    destination_port = 0

    protocol = "OTHER"

    first_time = None
    last_time = None


    # --------------------------------------------------------
    # Find first usable IP packet
    # --------------------------------------------------------

    for packet in packets:

        src, dst = get_ip_addresses(packet)

        if src is not None:

            source_ip = src
            destination_ip = dst

            break


    if source_ip is None:

        return None


    # --------------------------------------------------------
    # Process packets
    # --------------------------------------------------------

    for packet in packets:

        src, dst = get_ip_addresses(packet)

        if src is None:

            continue


        # Time

        try:

            packet_time = float(packet.time)

        except Exception:

            continue


        if first_time is None:

            first_time = packet_time

        last_time = packet_time


        # Packet length

        packet_length = len(packet)


        # Ports and protocol

        sport, dport, proto = get_ports(packet)


        if proto != "OTHER":

            protocol = proto


        # ----------------------------------------------------
        # Forward direction
        # ----------------------------------------------------

        if src == source_ip:

            forward_lengths.append(
                packet_length
            )

            if destination_port == 0:

                source_port = sport
                destination_port = dport


        # ----------------------------------------------------
        # Backward direction
        # ----------------------------------------------------

        elif dst == source_ip:

            backward_lengths.append(
                packet_length
            )


    # --------------------------------------------------------
    # Make sure packets existed
    # --------------------------------------------------------

    if first_time is None:

        return None


    # ========================================================
    # FLOW CALCULATIONS
    # ========================================================

    flow_duration = (
        last_time - first_time
    )


    # Avoid division by zero

    if flow_duration <= 0:

        flow_duration = 0.000001


    total_fwd_packets = len(
        forward_lengths
    )

    total_backward_packets = len(
        backward_lengths
    )


    total_length_fwd = sum(
        forward_lengths
    )

    total_length_bwd = sum(
        backward_lengths
    )


    total_packets = (
        total_fwd_packets
        +
        total_backward_packets
    )


    total_bytes = (
        total_length_fwd
        +
        total_length_bwd
    )


    flow_bytes_per_second = (
        total_bytes /
        flow_duration
    )


    flow_packets_per_second = (
        total_packets /
        flow_duration
    )


    # ========================================================
    # PACKET LENGTH STATISTICS
    # ========================================================

    all_lengths = (
        forward_lengths
        +
        backward_lengths
    )


    if all_lengths:

        packet_length_mean = float(
            np.mean(all_lengths)
        )

        packet_length_std = float(
            np.std(all_lengths)
        )

    else:

        packet_length_mean = 0.0
        packet_length_std = 0.0


    # Forward mean

    if forward_lengths:

        fwd_packet_length_mean = float(
            np.mean(forward_lengths)
        )

    else:

        fwd_packet_length_mean = 0.0


    # Backward mean

    if backward_lengths:

        bwd_packet_length_mean = float(
            np.mean(backward_lengths)
        )

    else:

        bwd_packet_length_mean = 0.0


    # ========================================================
    # CREATE FEATURE DATA
    # ========================================================

    feature_data = {

        "Destination Port":
            destination_port,

        "Flow Duration":
            flow_duration,

        "Total Fwd Packets":
            total_fwd_packets,

        "Total Backward Packets":
            total_backward_packets,

        "Total Length of Fwd Packets":
            total_length_fwd,

        "Total Length of Bwd Packets":
            total_length_bwd,

        "Flow Bytes/s":
            flow_bytes_per_second,

        "Flow Packets/s":
            flow_packets_per_second,

        "Packet Length Mean":
            packet_length_mean,

        "Packet Length Std":
            packet_length_std,

        "Fwd Packet Length Mean":
            fwd_packet_length_mean,

        "Bwd Packet Length Mean":
            bwd_packet_length_mean
    }


    # ========================================================
    # DATAFRAME
    # ========================================================

    data = pd.DataFrame(
        [feature_data]
    )


    # Ensure all training features exist

    for feature in features:

        if feature not in data.columns:

            data[feature] = 0


    # Keep exactly the training order

    data = data[features]


    return (
        data,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
    )


# ============================================================
# AI PREDICTION
# ============================================================

def predict_attack(data):

    prediction = model.predict(
        data
    )[0]


    probabilities = model.predict_proba(
        data
    )[0]


    attack_name = label_encoder.inverse_transform(
        [prediction]
    )[0]


    confidence = float(
        np.max(probabilities) * 100
    )


    return (
        attack_name,
        confidence
    )


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def calculate_security(
    attack_name,
    confidence
):

    attack_upper = (
        str(attack_name).upper()
    )


    # --------------------------------------------------------
    # BENIGN
    # --------------------------------------------------------

    if attack_upper == "BENIGN":

        risk_score = 5

        severity = "LOW"

        recommendation = (
            "Traffic appears normal. "
            "Continue monitoring."
        )


    # --------------------------------------------------------
    # PORTSCAN
    # --------------------------------------------------------

    elif attack_upper == "PORTSCAN":

        risk_score = min(
            80,
            int(50 + confidence * 0.30)
        )

        severity = "HIGH"

        recommendation = (
            "Investigate the source IP "
            "and monitor suspicious scanning activity."
        )


    # --------------------------------------------------------
    # DDOS
    # --------------------------------------------------------

    elif attack_upper == "DDOS":

        risk_score = min(
            100,
            int(70 + confidence * 0.30)
        )

        severity = "CRITICAL"

        recommendation = (
            "Investigate the source IP and "
            "consider blocking suspicious traffic."
        )


    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    else:

        risk_score = int(
            confidence * 0.50
        )

        severity = "MEDIUM"

        recommendation = (
            "Investigate the detected network activity."
        )


    return {
        "risk_score": risk_score,
        "severity": severity,
        "recommendation": recommendation
    }


# ============================================================
# SAVE ATTACK
# ============================================================

def save_attack_to_database(
    data,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    attack_name,
    confidence,
    security
):

    # Do not save normal traffic

    if str(attack_name).upper() == "BENIGN":

        print(
            "\nBENIGN traffic - "
            "not added to attack history."
        )

        return


    try:

        log_attack(

            source_ip=source_ip,

            destination_ip=destination_ip,

            source_port=source_port,

            destination_port=destination_port,

            protocol=protocol,

            attack_type=attack_name,

            confidence=confidence,

            risk_score=security["risk_score"],

            severity=security["severity"],

            recommendation=security["recommendation"],

            flow_duration=float(
                data["Flow Duration"].iloc[0]
            ),

            total_fwd_packets=int(
                data["Total Fwd Packets"].iloc[0]
            ),

            total_backward_packets=int(
                data["Total Backward Packets"].iloc[0]
            ),

            total_length_fwd_packets=float(
                data[
                    "Total Length of Fwd Packets"
                ].iloc[0]
            ),

            total_length_bwd_packets=float(
                data[
                    "Total Length of Bwd Packets"
                ].iloc[0]
            ),

            flow_bytes_per_second=float(
                data["Flow Bytes/s"].iloc[0]
            ),

            flow_packets_per_second=float(
                data["Flow Packets/s"].iloc[0]
            ),

            packet_length_mean=float(
                data["Packet Length Mean"].iloc[0]
            ),

            packet_length_std=float(
                data["Packet Length Std"].iloc[0]
            ),

            fwd_packet_length_mean=float(
                data[
                    "Fwd Packet Length Mean"
                ].iloc[0]
            ),

            bwd_packet_length_mean=float(
                data[
                    "Bwd Packet Length Mean"
                ].iloc[0]
            )
        )


        print(
            "\nAttack history updated successfully."
        )


    except Exception as error:

        print(
            "\nDatabase logging error:"
        )

        print(error)


# ============================================================
# DISPLAY RESULT
# ============================================================

def display_result(
    attack_name,
    confidence,
    security,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol
):

    print("\n")

    print("==========================================")
    print("          AI-NIDS DETECTION RESULT")
    print("==========================================")


    print(
        f"\nSource IP      : {source_ip}"
    )

    print(
        f"Destination IP : {destination_ip}"
    )

    print(
        f"Source Port    : {source_port}"
    )

    print(
        f"Destination Port: {destination_port}"
    )

    print(
        f"Protocol       : {protocol}"
    )

    print(
        f"Prediction     : {attack_name}"
    )

    print(
        f"Confidence     : {confidence:.2f}%"
    )

    print(
        f"Risk Score     : {security['risk_score']}"
    )

    print(
        f"Severity       : {security['severity']}"
    )

    print(
        f"Recommendation : "
        f"{security['recommendation']}"
    )


    print(
        "\n=========================================="
    )


# ============================================================
# ONE MONITORING CYCLE
# ============================================================

def start_monitoring():

    print("\n==========================================")
    print("        LIVE NETWORK MONITORING")
    print("==========================================")


    print("\nCapturing live packets...")

    print(
        f"Packet limit : {PACKET_COUNT}"
    )

    print(
        f"Timeout      : {CAPTURE_TIMEOUT} seconds"
    )

    print(
        "\nPress CTRL+C to stop.\n"
    )


    # --------------------------------------------------------
    # Capture
    # --------------------------------------------------------

    try:

        packets = sniff(
            count=PACKET_COUNT,
            timeout=CAPTURE_TIMEOUT
        )


    except PermissionError:

        print(
            "\nERROR: Permission denied."
        )

        print(
            "Run Command Prompt as "
            "Administrator."
        )

        return


    except Exception as error:

        print(
            "\nPacket capture error:"
        )

        print(error)

        return


    print(
        f"\nPackets captured: {len(packets)}"
    )


    if len(packets) == 0:

        print(
            "\nNo packets captured."
        )

        print(
            "Generate network activity "
            "and try again."
        )

        return


    # ========================================================
    # EXTRACT FEATURES
    # ========================================================

    print(
        "\nExtracting network-flow features..."
    )


    result = extract_flow_features(
        packets
    )


    if result is None:

        print(
            "\nCould not extract flow features."
        )

        return


    (
        data,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
    ) = result


    print(
        "12 flow features prepared successfully."
    )


    # ========================================================
    # DISPLAY FEATURES
    # ========================================================

    print(
        "\nFeature values:"
    )


    for feature in features:

        value = data[
            feature
        ].iloc[0]

        print(
            f"{feature:<35} : {value}"
        )


    # ========================================================
    # AI PREDICTION
    # ========================================================

    print(
        "\nRunning Random Forest AI..."
    )


    try:

        (
            attack_name,
            confidence
        ) = predict_attack(
            data
        )


    except Exception as error:

        print(
            "\nPrediction error:"
        )

        print(error)

        return


    # ========================================================
    # SECURITY ANALYSIS
    # ========================================================

    security = calculate_security(
        attack_name,
        confidence
    )


    # ========================================================
    # SAVE ATTACK
    # ========================================================

    save_attack_to_database(

        data=data,

        source_ip=source_ip,

        destination_ip=destination_ip,

        source_port=source_port,

        destination_port=destination_port,

        protocol=protocol,

        attack_name=attack_name,

        confidence=confidence,

        security=security
    )


    # ========================================================
    # DISPLAY
    # ========================================================

    display_result(

        attack_name=attack_name,

        confidence=confidence,

        security=security,

        source_ip=source_ip,

        destination_ip=destination_ip,

        source_port=source_port,

        destination_port=destination_port,

        protocol=protocol
    )


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    try:

        while True:

            start_monitoring()


            print(
                "\nWaiting 3 seconds "
                "before next capture..."
            )


            time.sleep(3)


    except KeyboardInterrupt:

        print("\n")

        print("==========================================")
        print("       AI-NIDS MONITOR STOPPED")
        print("==========================================")