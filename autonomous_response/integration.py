"""
Member 4 - Autonomous Response Integration

Connects:
Member 2 Detection
        ↓
Member 4 Response Engine
        ↓
Member 3 Database
"""

import requests

from member2_detection_engine.integration import inspect_request

from .response import decide_action
from .ip_blocker import block_ip
from .alert_manager import create_alert


# Member 3 backend
DATABASE_API_URL = "http://127.0.0.1:8000/api/log"


def save_to_database(request_data, verdict, action_result):
    """
    Send the security event to Member 3 backend.
    """

    # Convert Member 4 action names to Member 3 database format
    action_mapping = {
        "ALLOW": "allowed",
        "MONITOR": "monitored",
        "BLOCK": "blocked"
    }

    action = action_mapping.get(
        action_result["action"],
        action_result["action"].lower()
    )

    status_mapping = {
        "NORMAL": "normal",
        "SUSPICIOUS": "suspicious",
        "MALICIOUS": "malicious"
    }

    status = status_mapping.get(
        verdict.get("risk_level"),
        "normal"
    )

    log_data = {
        "request_id": request_data.get("request_id"),
        "ip_address": verdict.get("ip"),
        "method": request_data.get("method"),
        "endpoint": request_data.get("endpoint"),
        "attack_type": verdict.get("attack_type"),
        "risk_score": verdict.get("risk_score"),
        "confidence": verdict.get("confidence"),
        "status": status,
        "action": action
    }

    try:
        response = requests.post(
            DATABASE_API_URL,
            json=log_data,
            timeout=5
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as error:
        print(f"Database logging failed: {error}")
        return None


def process_request(request_data):
    """
    Complete Member 2 -> Member 4 -> Member 3 pipeline.

    Flow:
        Request
        ↓
        Member 2 Detection
        ↓
        Member 4 Decision
        ↓
        Block / Monitor / Allow
        ↓
        Alert
        ↓
        Member 3 Database
    """

    # STEP 1: Member 2 detection
    verdict = inspect_request(request_data)

    # STEP 2: Member 4 decides action
    action_result = decide_action(verdict)

    # STEP 3: Block IP if required
    if action_result["action"] == "BLOCK":
        block_ip(action_result["ip"])

    # STEP 4: Create alert for suspicious/malicious requests
    if action_result["action"] in ("MONITOR", "BLOCK"):
        alert = create_alert(verdict, action_result)
    else:
        alert = None

    # STEP 5: Save event into Member 3 database
    database_result = save_to_database(
        request_data,
        verdict,
        action_result
    )

    # STEP 6: Return complete result
    return {
        "verdict": verdict,
        "response": action_result,
        "alert": alert,
        "database": database_result
    }