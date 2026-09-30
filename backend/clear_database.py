import sqlite3
import os


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROJECT_DIR = os.path.dirname(BASE_DIR)

DATABASE_PATH = os.path.join(
    PROJECT_DIR,
    "model",
    "attack_history.db"
)


print("\n==========================================")
print("       AI-NIDS DATABASE CLEANUP")
print("==========================================")

print("\nDatabase:")
print(DATABASE_PATH)


if not os.path.exists(DATABASE_PATH):

    print("\nDatabase not found!")

else:

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM attack_history"
    )

    connection.commit()

    print(
        "\nAll test attack records deleted."
    )

    cursor.execute(
        "SELECT COUNT(*) FROM attack_history"
    )

    count = cursor.fetchone()[0]

    print(
        "Remaining records:",
        count
    )

    connection.close()


print("\nDatabase cleanup completed.")