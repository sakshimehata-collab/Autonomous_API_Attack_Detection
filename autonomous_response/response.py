"""
Member 4 - Autonomous Response Engine

Receives the verdict from Member 2 and decides what action
should be taken against the request.
"""


def decide_action(verdict):
    """
    Decide the appropriate response based on Member 2's verdict.

    Risk score:
        0-29   -> ALLOW
        30-69  -> MONITOR
        70-100 -> BLOCK
    """

    risk_score = verdict.get("risk_score", 0)
    ip = verdict.get("ip")

    if risk_score >= 70:
        action = "BLOCK"
        severity = "HIGH"

    elif risk_score >= 30:
        action = "MONITOR"
        severity = "MEDIUM"

    else:
        action = "ALLOW"
        severity = "LOW"

    return {
        "action": action,
        "severity": severity,
        "ip": ip,
        "risk_score": risk_score,
        "attack_type": verdict.get("attack_type"),
        "confidence": verdict.get("confidence"),
        "risk_level": verdict.get("risk_level"),
        "is_malicious": verdict.get("is_malicious"),
    }