import sqlite3
from pathlib import Path


# ==============================
# DATABASE LOCATION
# ==============================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"

DATABASE_PATH = DATA_DIR / "security.db"


# Create data folder automatically
DATA_DIR.mkdir(exist_ok=True)


# ==============================
# DATABASE CONNECTION
# ==============================

def get_connection():

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    return connection


# ==============================
# INITIALIZE DATABASE
# ==============================

def initialize_database():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            request_id TEXT,

            ip_address TEXT NOT NULL,

            method TEXT,

            endpoint TEXT,

            attack_type TEXT,

            risk_score REAL,

            confidence REAL,

            status TEXT,

            action TEXT,

            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP

        )
    """)

    connection.commit()

    connection.close()


# ==============================
# INSERT SECURITY LOG
# ==============================

def insert_log(data):

    connection = get_connection()

    cursor = connection.execute("""

        INSERT INTO security_logs (

            request_id,
            ip_address,
            method,
            endpoint,
            attack_type,
            risk_score,
            confidence,
            status,
            action

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (

        data.get("request_id"),

        data.get("ip_address"),

        data.get("method"),

        data.get("endpoint"),

        data.get("attack_type"),

        data.get("risk_score"),

        data.get("confidence"),

        data.get("status"),

        data.get("action")

    ))

    connection.commit()

    log_id = cursor.lastrowid

    connection.close()

    return log_id


# ==============================
# GET ALL SECURITY LOGS
# ==============================

def get_all_logs():

    connection = get_connection()

    cursor = connection.execute("""

        SELECT *

        FROM security_logs

        ORDER BY id DESC

    """)

    logs = [dict(row) for row in cursor.fetchall()]

    connection.close()

    return logs


# ==============================
# GET DASHBOARD STATISTICS
# ==============================

def get_statistics():

    connection = get_connection()


    total_requests = connection.execute("""

        SELECT COUNT(*)

        FROM security_logs

    """).fetchone()[0]


    attacks_detected = connection.execute("""

        SELECT COUNT(*)

        FROM security_logs

        WHERE status = 'malicious'

    """).fetchone()[0]


    blocked_requests = connection.execute("""

        SELECT COUNT(*)

        FROM security_logs

        WHERE action = 'blocked'

    """).fetchone()[0]


    allowed_requests = connection.execute("""

        SELECT COUNT(*)

        FROM security_logs

        WHERE action = 'allowed'

    """).fetchone()[0]


    connection.close()


    return {

        "total_requests": total_requests,

        "attacks_detected": attacks_detected,

        "blocked_requests": blocked_requests,

        "allowed_requests": allowed_requests

    }