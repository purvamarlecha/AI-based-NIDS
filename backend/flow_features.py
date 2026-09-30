import numpy as np


# ==========================================
# CREATE FLOW KEY
# ==========================================

def create_flow_key(packet):
    """
    Creates a unique bidirectional identifier
    for a network flow.
    """

    if not packet.haslayer("IP"):
        return None

    src_ip = packet["IP"].src
    dst_ip = packet["IP"].dst

    protocol = packet["IP"].proto

    src_port = 0
    dst_port = 0

    # TCP
    if packet.haslayer("TCP"):

        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport

    # UDP
    elif packet.haslayer("UDP"):

        src_port = packet["UDP"].sport
        dst_port = packet["UDP"].dport


    # --------------------------------------
    # Make flow bidirectional
    # --------------------------------------

    endpoint1 = (
        src_ip,
        src_port
    )

    endpoint2 = (
        dst_ip,
        dst_port
    )

    if endpoint1 <= endpoint2:

        first = endpoint1
        second = endpoint2

    else:

        first = endpoint2
        second = endpoint1


    return (
        first,
        second,
        protocol
    )


# ==========================================
# CALCULATE FLOW FEATURES
# ==========================================

def calculate_flow_features(flow):
    """
    Calculates the 12 features required
    by the trained Random Forest model.
    """

    packets = flow.get("packets", [])


    # --------------------------------------
    # Check packets
    # --------------------------------------

    if len(packets) == 0:
        return None


    # --------------------------------------
    # Flow timing
    # --------------------------------------

    start_time = flow["start_time"]

    # Use last packet time instead of time.time()
    # so the feature represents the actual flow.

    end_time = flow.get(
        "last_seen",
        start_time
    )

    duration = end_time - start_time


    if duration <= 0:

        duration = 0.001


    # --------------------------------------
    # Source IP
    # --------------------------------------

    source_ip = flow["source_ip"]


    # --------------------------------------
    # Forward / Backward packets
    # --------------------------------------

    forward_packets = []
    backward_packets = []


    for packet in packets:

        if not packet.haslayer("IP"):
            continue


        packet_source = packet["IP"].src


        if packet_source == source_ip:

            forward_packets.append(
                packet
            )

        else:

            backward_packets.append(
                packet
            )


    # --------------------------------------
    # Packet lengths
    # --------------------------------------

    forward_lengths = [
        len(packet)
        for packet in forward_packets
    ]


    backward_lengths = [
        len(packet)
        for packet in backward_packets
    ]


    all_lengths = [
        len(packet)
        for packet in packets
        if packet.haslayer("IP")
    ]


    # --------------------------------------
    # Safety check
    # --------------------------------------

    if not all_lengths:
        return None


    # --------------------------------------
    # Packet counts
    # --------------------------------------

    total_fwd_packets = len(
        forward_packets
    )

    total_bwd_packets = len(
        backward_packets
    )


    # --------------------------------------
    # Total bytes
    # --------------------------------------

    total_fwd_bytes = sum(
        forward_lengths
    )

    total_bwd_bytes = sum(
        backward_lengths
    )


    total_bytes = (
        total_fwd_bytes
        + total_bwd_bytes
    )


    # --------------------------------------
    # Flow rates
    # --------------------------------------

    flow_bytes_per_second = (
        total_bytes / duration
    )


    flow_packets_per_second = (
        len(all_lengths) / duration
    )


    # --------------------------------------
    # Packet statistics
    # --------------------------------------

    packet_length_mean = float(
        np.mean(all_lengths)
    )


    packet_length_std = float(
        np.std(all_lengths)
    )


    # --------------------------------------
    # Forward packet mean
    # --------------------------------------

    if forward_lengths:

        fwd_packet_length_mean = float(
            np.mean(forward_lengths)
        )

    else:

        fwd_packet_length_mean = 0.0


    # --------------------------------------
    # Backward packet mean
    # --------------------------------------

    if backward_lengths:

        bwd_packet_length_mean = float(
            np.mean(backward_lengths)
        )

    else:

        bwd_packet_length_mean = 0.0


    # --------------------------------------
    # Destination port
    # --------------------------------------

    destination_port = flow.get(
        "destination_port",
        0
    )


    # ======================================
    # RETURN MODEL FEATURES
    # ======================================

    return {

        "Destination Port":
            destination_port,

        "Flow Duration":
            duration,

        "Total Fwd Packets":
            total_fwd_packets,

        "Total Backward Packets":
            total_bwd_packets,

        "Total Length of Fwd Packets":
            total_fwd_bytes,

        "Total Length of Bwd Packets":
            total_bwd_bytes,

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