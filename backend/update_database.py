import sqlite3
import os


# ============================================================
# DATABASE PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_DIR = os.path.dirname(
    BASE_DIR
)

DATABASE_PATH = os.path.join(
    PROJECT_DIR,
    "model",
    "attack_history.db"
)


print("\n==========================================")
print("       AI-NIDS DATABASE UPDATE")
print("==========================================")

print("\nDatabase:")
print(DATABASE_PATH)


# ============================================================
# CONNECT DATABASE
# ============================================================

connection = sqlite3.connect(
    DATABASE_PATH
)

cursor = connection.cursor()


# ============================================================
# NEW FEATURE COLUMNS
# ============================================================

columns = {

    "flow_duration":
        "REAL DEFAULT 0",

    "total_fwd_packets":
        "REAL DEFAULT 0",

    "total_backward_packets":
        "REAL DEFAULT 0",

    "total_length_fwd_packets":
        "REAL DEFAULT 0",

    "total_length_bwd_packets":
        "REAL DEFAULT 0",

    "flow_bytes_per_second":
        "REAL DEFAULT 0",

    "flow_packets_per_second":
        "REAL DEFAULT 0",

    "packet_length_mean":
        "REAL DEFAULT 0",

    "packet_length_std":
        "REAL DEFAULT 0",

    "fwd_packet_length_mean":
        "REAL DEFAULT 0",

    "bwd_packet_length_mean":
        "REAL DEFAULT 0"

}


# ============================================================
# GET EXISTING COLUMNS
# ============================================================

cursor.execute(
    "PRAGMA table_info(attack_history)"
)

existing_columns = [

    row[1]

    for row in cursor.fetchall()

]


# ============================================================
# ADD MISSING COLUMNS
# ============================================================

for column, data_type in columns.items():

    if column not in existing_columns:

        print(
            "Adding column:",
            column
        )

        cursor.execute(
            f"""
            ALTER TABLE attack_history
            ADD COLUMN {column} {data_type}
            """
        )

    else:

        print(
            "Already exists:",
            column
        )


# ============================================================
# SAVE CHANGES
# ============================================================

connection.commit()

connection.close()


print("\n==========================================")
print("       DATABASE UPDATE COMPLETE")
print("==========================================")

print("\nFlow feature columns are ready.")

print("\nAI-NIDS can now store:")

for column in columns:

    print(
        "-",
        column
    )

print("\nDatabase update completed successfully!")