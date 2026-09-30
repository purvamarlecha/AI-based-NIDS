from flask import Flask, jsonify, send_from_directory, request, session, redirect
import os
import sqlite3
import random
import joblib
import pandas as pd

from xai_explainer import explain_prediction


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

# Required for login/OTP sessions
app.secret_key = "AI-NIDS-College-Project-Secret-Key"


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

FRONTEND_DIR = os.path.join(
    PROJECT_DIR,
    "frontend"
)

MODEL_DIR = os.path.join(
    PROJECT_DIR,
    "model"
)

DATABASE_PATH = os.path.join(
    MODEL_DIR,
    "attack_history.db"
)

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
# DATABASE HELPER
# ============================================================

def get_database_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# LOGIN PAGE
# ============================================================

@app.route("/login")
def login_page():

    login_file = os.path.join(
        FRONTEND_DIR,
        "login.html"
    )

    if not os.path.exists(login_file):

        return jsonify({
            "success": False,
            "message": "frontend/login.html not found."
        }), 500

    return send_from_directory(
        FRONTEND_DIR,
        "login.html"
    )


# ============================================================
# OTP PAGE
# ============================================================

@app.route("/otp")
def otp_page():

    # User must login first
    if not session.get("login"):

        return redirect("/login")

    otp_file = os.path.join(
        FRONTEND_DIR,
        "otp.html"
    )

    if not os.path.exists(otp_file):

        return jsonify({
            "success": False,
            "message": "frontend/otp.html not found."
        }), 500

    return send_from_directory(
        FRONTEND_DIR,
        "otp.html"
    )


# ============================================================
# LOGIN API
# ============================================================

@app.route(
    "/api/login",
    methods=["POST"]
)
def login_api():

    try:

        print("\n==========================================")
        print("             AI-NIDS LOGIN")
        print("==========================================")

        data = request.get_json(
            silent=True
        ) or {}

        username = str(
            data.get("username", "")
        ).strip()

        password = str(
            data.get("password", "")
        )

        print("Login request received")
        print("Username:", username)

        # ----------------------------------------------------
        # DEMO LOGIN
        # ----------------------------------------------------

        if (
            username == "admin"
            and password == "admin123"
        ):

            # Generate 6 digit OTP
            otp = str(
                random.randint(
                    100000,
                    999999
                )
            )

            # Clear previous session
            session.clear()

            # Save login information
            session["login"] = True
            session["otp"] = otp
            session["username"] = username

            print("\nOTP GENERATED SUCCESSFULLY")
            print("------------------------------------------")
            print("Username :", username)
            print("OTP      :", otp)
            print("------------------------------------------")
            print("==========================================\n")

            return jsonify({
                "success": True,
                "message": "Login successful. OTP generated."
            })

        # ----------------------------------------------------
        # INVALID LOGIN
        # ----------------------------------------------------

        print("Invalid username/password")

        return jsonify({
            "success": False,
            "message": "Invalid username or password."
        }), 401

    except Exception as error:

        print("\nLOGIN ERROR:")
        print(error)

        return jsonify({
            "success": False,
            "message": "Login failed."
        }), 500


# ============================================================
# OTP VERIFICATION API
# ============================================================

@app.route(
    "/api/verify-otp",
    methods=["POST"]
)
def verify_otp():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        entered_otp = str(
            data.get("otp", "")
        ).strip()

        saved_otp = session.get("otp")

        print("\n==========================================")
        print("          OTP VERIFICATION")
        print("==========================================")

        print(
            "Entered OTP:",
            entered_otp
        )

        if (
            session.get("login")
            and saved_otp
            and entered_otp == saved_otp
        ):

            # Authentication successful
            session["authenticated"] = True

            # OTP is no longer required
            session.pop(
                "otp",
                None
            )

            print(
                "OTP VERIFIED SUCCESSFULLY"
            )

            print(
                "User:",
                session.get("username")
            )

            print(
                "==========================================\n"
            )

            return jsonify({
                "success": True,
                "message": "Two-step verification successful."
            })

        print("INVALID OTP")

        return jsonify({
            "success": False,
            "message": "Invalid OTP. Check the Flask terminal."
        }), 401

    except Exception as error:

        print(
            "OTP ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": "OTP verification failed."
        }), 500


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/api/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully."
    })


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    # Dashboard requires OTP verification
    if not session.get("authenticated"):

        return redirect("/login")

    index_file = os.path.join(
        FRONTEND_DIR,
        "index.html"
    )

    if not os.path.exists(index_file):

        return jsonify({
            "success": False,
            "message": "frontend/index.html not found."
        }), 500

    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


# ============================================================
# STATUS API
# ============================================================

@app.route("/api/status")
def status():

    return jsonify({

        "status": "Running",

        "message":
            "AI-NIDS backend is working",

        "model":
            "Random Forest",

        "model_available":
            os.path.exists(MODEL_PATH),

        "database_available":
            os.path.exists(DATABASE_PATH),

        "classes": [
            "BENIGN",
            "DDoS",
            "PortScan"
        ]

    })


# ============================================================
# ATTACK HISTORY API
# ============================================================

@app.route("/api/attacks")
def attacks():

    connection = None

    try:

        print("\n==========================================")
        print("        ATTACK HISTORY REQUEST")
        print("==========================================")

        print(
            "Database:",
            DATABASE_PATH
        )

        if not os.path.exists(
            DATABASE_PATH
        ):

            return jsonify({
                "success": False,
                "message": "Database not found.",
                "records": []
            }), 500

        connection = get_database_connection()

        cursor = connection.cursor()

        # Check table
        cursor.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type='table'
            AND name='attack_history'
        """)

        if cursor.fetchone() is None:

            return jsonify({
                "success": False,
                "message": "attack_history table not found.",
                "records": []
            }), 500

        # Get attacks
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

        records = [
            dict(row)
            for row in cursor.fetchall()
        ]

        print(
            "Attack records returned:",
            len(records)
        )

        # IMPORTANT:
        # Return array directly because
        # your existing dashboard expects it.
        return jsonify(records)

    except Exception as error:

        print(
            "Attack history error:",
            error
        )

        return jsonify([])

    finally:

        if connection:

            connection.close()


# ============================================================
# STATISTICS API
# ============================================================

@app.route("/api/statistics")
def statistics():

    connection = None

    try:

        if not os.path.exists(
            DATABASE_PATH
        ):

            return jsonify({
                "total": 0,
                "ddos": 0,
                "portscan": 0,
                "benign": 0,
                "critical": 0
            })

        connection = get_database_connection()

        cursor = connection.cursor()

        # Total
        cursor.execute("""
            SELECT COUNT(*)
            FROM attack_history
        """)

        total = cursor.fetchone()[0]

        # DDoS
        cursor.execute("""
            SELECT COUNT(*)
            FROM attack_history
            WHERE UPPER(
                COALESCE(attack_type, '')
            ) = 'DDOS'
        """)

        ddos = cursor.fetchone()[0]

        # PortScan
        cursor.execute("""
            SELECT COUNT(*)
            FROM attack_history
            WHERE UPPER(
                COALESCE(attack_type, '')
            ) = 'PORTSCAN'
        """)

        portscan = cursor.fetchone()[0]

        # Benign
        cursor.execute("""
            SELECT COUNT(*)
            FROM attack_history
            WHERE UPPER(
                COALESCE(attack_type, '')
            ) = 'BENIGN'
        """)

        benign = cursor.fetchone()[0]

        # Critical
        cursor.execute("""
            SELECT COUNT(*)
            FROM attack_history
            WHERE UPPER(
                COALESCE(severity, '')
            ) = 'CRITICAL'
        """)

        critical = cursor.fetchone()[0]

        return jsonify({

            "total": total,

            "ddos": ddos,

            "portscan": portscan,

            "benign": benign,

            "critical": critical

        })

    except Exception as error:

        print(
            "Statistics error:",
            error
        )

        return jsonify({
            "total": 0,
            "ddos": 0,
            "portscan": 0,
            "benign": 0,
            "critical": 0
        })

    finally:

        if connection:

            connection.close()


# ============================================================
# XAI EXPLANATION API
# ============================================================

@app.route(
    "/api/xai",
    methods=["GET"]
)
def xai_explanation():

    connection = None

    try:

        print("\n==========================================")
        print("             XAI API REQUEST")
        print("==========================================")

        # ----------------------------------------------------
        # CHECK MODEL FILES
        # ----------------------------------------------------

        required_files = [

            (
                MODEL_PATH,
                "AI model"
            ),

            (
                ENCODER_PATH,
                "Label encoder"
            ),

            (
                FEATURES_PATH,
                "Features file"
            )

        ]

        for path, label in required_files:

            if not os.path.exists(path):

                return jsonify({
                    "success": False,
                    "message":
                        f"{label} not found: {path}"
                }), 500

        # ----------------------------------------------------
        # LOAD MODEL
        # ----------------------------------------------------

        print(
            "Loading AI model..."
        )

        model = joblib.load(
            MODEL_PATH
        )

        label_encoder = joblib.load(
            ENCODER_PATH
        )

        features = joblib.load(
            FEATURES_PATH
        )

        print(
            "Features:",
            len(features)
        )

        print(
            "Classes:",
            list(
                label_encoder.classes_
            )
        )

        # ----------------------------------------------------
        # DATABASE
        # ----------------------------------------------------

        if not os.path.exists(
            DATABASE_PATH
        ):

            return jsonify({
                "success": False,
                "message":
                    "Database not found: "
                    + DATABASE_PATH
            }), 500

        connection = get_database_connection()

        cursor = connection.cursor()

        # ----------------------------------------------------
        # SELECT ATTACK
        # ----------------------------------------------------

        attack_id = request.args.get(
            "id",
            ""
        ).strip()

        if attack_id:

            try:

                attack_id = int(
                    attack_id
                )

            except ValueError:

                return jsonify({
                    "success": False,
                    "message":
                        "Invalid attack ID."
                }), 400

            print(
                "Selected attack ID:",
                attack_id
            )

            cursor.execute("""
                SELECT *
                FROM attack_history
                WHERE id = ?
                LIMIT 1
            """, (
                attack_id,
            ))

        else:

            print(
                "No attack ID supplied."
            )

            print(
                "Using latest attack."
            )

            cursor.execute("""
                SELECT *
                FROM attack_history
                ORDER BY id DESC
                LIMIT 1
            """)

        attack = cursor.fetchone()

        if attack is None:

            return jsonify({
                "success": False,
                "message":
                    "Attack record not found."
            }), 404

        attack_data = dict(
            attack
        )

        print(
            "Attack selected:",
            attack_data.get(
                "attack_type"
            )
        )

        # ----------------------------------------------------
        # CREATE MODEL FEATURES
        # ----------------------------------------------------

        feature_data = {

            "Destination Port":
                attack_data.get(
                    "destination_port",
                    0
                ) or 0,

            "Flow Duration":
                attack_data.get(
                    "flow_duration",
                    0
                ) or 0,

            "Total Fwd Packets":
                attack_data.get(
                    "total_fwd_packets",
                    0
                ) or 0,

            "Total Backward Packets":
                attack_data.get(
                    "total_backward_packets",
                    0
                ) or 0,

            "Total Length of Fwd Packets":
                attack_data.get(
                    "total_length_fwd_packets",
                    0
                ) or 0,

            "Total Length of Bwd Packets":
                attack_data.get(
                    "total_length_bwd_packets",
                    0
                ) or 0,

            "Flow Bytes/s":
                attack_data.get(
                    "flow_bytes_per_second",
                    0
                ) or 0,

            "Flow Packets/s":
                attack_data.get(
                    "flow_packets_per_second",
                    0
                ) or 0,

            "Packet Length Mean":
                attack_data.get(
                    "packet_length_mean",
                    0
                ) or 0,

            "Packet Length Std":
                attack_data.get(
                    "packet_length_std",
                    0
                ) or 0,

            "Fwd Packet Length Mean":
                attack_data.get(
                    "fwd_packet_length_mean",
                    0
                ) or 0,

            "Bwd Packet Length Mean":
                attack_data.get(
                    "bwd_packet_length_mean",
                    0
                ) or 0

        }

        data = pd.DataFrame(
            [feature_data]
        )

        # ----------------------------------------------------
        # MATCH MODEL FEATURES
        # ----------------------------------------------------

        for feature in features:

            if feature not in data.columns:

                data[feature] = 0

        data = data[
            features
        ]

        # ----------------------------------------------------
        # CLEAN DATA
        # ----------------------------------------------------

        data = data.replace(
            [
                float("inf"),
                float("-inf")
            ],
            0
        ).fillna(0)

        # ----------------------------------------------------
        # PREDICTION
        # ----------------------------------------------------

        prediction = model.predict(
            data
        )

        prediction_label = (
            label_encoder
            .inverse_transform(
                prediction
            )[0]
        )

        # ----------------------------------------------------
        # CONFIDENCE
        # ----------------------------------------------------

        confidence = 0.0

        if hasattr(
            model,
            "predict_proba"
        ):

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

        # ----------------------------------------------------
        # XAI
        # ----------------------------------------------------

        explanation = explain_prediction(
            model,
            data,
            features,
            label_encoder
        )

        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        result = {

            "success": True,

            "id":
                attack_data.get(
                    "id"
                ),

            "attack_type":
                attack_data.get(
                    "attack_type",
                    "Unknown"
                ),

            "prediction":
                prediction_label,

            "confidence":
                round(
                    confidence,
                    2
                ),

            "source_ip":
                attack_data.get(
                    "source_ip",
                    "-"
                ),

            "destination_ip":
                attack_data.get(
                    "destination_ip",
                    "-"
                ),

            "source_port":
                attack_data.get(
                    "source_port",
                    0
                ),

            "destination_port":
                attack_data.get(
                    "destination_port",
                    0
                ),

            "protocol":
                attack_data.get(
                    "protocol",
                    "-"
                ),

            "severity":
                attack_data.get(
                    "severity",
                    "-"
                ),

            "risk_score":
                attack_data.get(
                    "risk_score",
                    0
                ),

            "recommendation":
                attack_data.get(
                    "recommendation",
                    "-"
                ),

            "explanation":
                explanation,

            "features":
                feature_data

        }

        print(
            "Prediction:",
            prediction_label
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
            "XAI API completed successfully."
        )

        return jsonify(
            result
        )

    except Exception as error:

        print(
            "\nXAI API ERROR:",
            error
        )

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500

    finally:

        if connection:

            connection.close()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/api/health")
def health():

    return jsonify({

        "success": True,

        "backend": "online",

        "database":
            os.path.exists(
                DATABASE_PATH
            ),

        "model":
            os.path.exists(
                MODEL_PATH
            ),

        "encoder":
            os.path.exists(
                ENCODER_PATH
            ),

        "features":
            os.path.exists(
                FEATURES_PATH
            )

    })


# ============================================================
# RUN FLASK SERVER
# ============================================================

if __name__ == "__main__":

    print("\n==========================================")
    print("          AI-NIDS SECURITY CENTER")
    print("==========================================")

    print("\nProject directory:")
    print(PROJECT_DIR)

    print("\nFrontend:")
    print(FRONTEND_DIR)

    print("\nDatabase:")
    print(DATABASE_PATH)

    print("\nAI Model:")
    print(MODEL_PATH)

    print("\n==========================================")

    print("\nLOGIN URL:")
    print("http://127.0.0.1:5000/login")

    print("\nDASHBOARD URL:")
    print("http://127.0.0.1:5000")

    print("\nATTACK HISTORY:")
    print("http://127.0.0.1:5000/api/attacks")

    print("\nSTATISTICS:")
    print("http://127.0.0.1:5000/api/statistics")

    print("\nXAI:")
    print("http://127.0.0.1:5000/api/xai")

    print("\nHEALTH:")
    print("http://127.0.0.1:5000/api/health")

    print("\n==========================================")

    print("\nDEMO LOGIN")
    print("Username: admin")
    print("Password: admin123")

    print("\n==========================================")
    print("Press CTRL+C to stop.")
    print("==========================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )