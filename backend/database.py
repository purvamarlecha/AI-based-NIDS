import os
import sqlite3


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

DATABASE_PATH = os.path.join(
    PROJECT_DIR,
    "model",
    "attack_history.db"
)


def log_attack(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    attack_type,
    confidence,
    risk_score,
    severity,
    recommendation,
    flow_duration=0,
    total_fwd_packets=0,
    total_backward_packets=0,
    total_length_fwd_packets=0,
    total_length_bwd_packets=0,
    flow_bytes_per_second=0,
    flow_packets_per_second=0,
    packet_length_mean=0,
    packet_length_std=0,
    fwd_packet_length_mean=0,
    bwd_packet_length_mean=0
):

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO attack_history (
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
            recommendation,
            flow_duration,
            total_fwd_packets,
            total_backward_packets,
            total_length_fwd_packets,
            total_length_bwd_packets,
            flow_bytes_per_second,
            flow_packets_per_second,
            packet_length_mean,
            packet_length_std,
            fwd_packet_length_mean,
            bwd_packet_length_mean
        )
        VALUES (
            datetime('now'),
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            attack_type,
            confidence,
            risk_score,
            severity,
            recommendation,
            flow_duration,
            total_fwd_packets,
            total_backward_packets,
            total_length_fwd_packets,
            total_length_bwd_packets,
            flow_bytes_per_second,
            flow_packets_per_second,
            packet_length_mean,
            packet_length_std,
            fwd_packet_length_mean,
            bwd_packet_length_mean
        )
    )

    connection.commit()
    connection.close()

    print("[DATABASE] Attack saved successfully.")