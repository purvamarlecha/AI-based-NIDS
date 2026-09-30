import sqlite3
import os
from datetime import datetime


# ============================================================
# DATABASE PATH
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROJECT_DIR = os.path.dirname(BASE_DIR)

MODEL_DIR = os.path.join(PROJECT_DIR, "model")

os.makedirs(MODEL_DIR, exist_ok=True)

DATABASE_PATH = os.path.join(
    MODEL_DIR,
    "attack_history.db"
)


# ============================================================
# CREATE DATABASE
# ============================================================

def create_database():

    connection = sqlite3.connect(DATABASE_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            source_port INTEGER,

            destination_port INTEGER,

            protocol TEXT,

            attack_type TEXT,

            confidence REAL,

            risk_score INTEGER,

            severity TEXT,

            recommendation TEXT

        )
    """)

    connection.commit()

    connection.close()


# ============================================================
# LOG ATTACK
# ============================================================

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
    recommendation
):

    try:

        create_database()

        connection = sqlite3.connect(DATABASE_PATH)

        cursor = connection.cursor()

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        cursor.execute("""
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
                recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (

            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            attack_type,
            float(confidence),
            int(risk_score),
            severity,
            recommendation

        ))

        connection.commit()

        connection.close()

        print(
            "\n[DATABASE] Attack saved successfully."
        )

        return True

    except Exception as error:

        print(
            "\n[DATABASE ERROR]:",
            error
        )

        return False


# ============================================================
# GET ATTACK HISTORY
# ============================================================

def get_attack_history():

    try:

        create_database()

        connection = sqlite3.connect(
            DATABASE_PATH
        )

        connection.row_factory = sqlite3.Row

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
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
            FROM attack_history
            ORDER BY id DESC
        """)

        rows = cursor.fetchall()

        connection.close()

        return [
            dict(row)
            for row in rows
        ]

    except Exception as error:

        print(
            "\n[DATABASE ERROR]:",
            error
        )

        return []


# ============================================================
# TEST DATABASE
# ============================================================

if __name__ == "__main__":

    print("\n==========================================")
    print("       AI-NIDS DATABASE TEST")
    print("==========================================")

    print("\nDatabase location:")
    print(DATABASE_PATH)

    create_database()

    print("\nDatabase created successfully!")

    records = get_attack_history()

    print(
        "\nExisting attack records:",
        len(records)
    )

    print("\nAdding test attack...")

    log_attack(
        source_ip="192.168.1.100",
        destination_ip="192.168.1.1",
        source_port=12345,
        destination_port=80,
        protocol="TCP",
        attack_type="DDoS",
        confidence=99.5,
        risk_score=95,
        severity="CRITICAL",
        recommendation="Block the suspicious source IP and investigate the traffic."
    )

    print("\nChecking database again...")

    records = get_attack_history()

    print("Total records:", len(records))

    for record in records:
        print(record)

    print("\nDatabase test completed.")