"""Public detection API for Member 2.

    from member2_detection_engine import detect_attack
    result = detect_attack({"ip": "1.2.3.4", "method": "POST",
                            "endpoint": "/login", "payload": "u=a' OR 1=1 --"})

Risk score (documented, deterministic):
    p_mal      = 1 - P(NORMAL)           # from RandomForest predict_proba
    risk_score = round(100 * p_mal)      # 0..100
    NORMAL     0-29   | SUSPICIOUS 30-69 | MALICIOUS 70-100
    is_malicious = predicted class != NORMAL AND risk_score >= 70
"""
import os
import time
from collections import defaultdict, deque
from typing import Any, Dict

import joblib
import pandas as pd

from .feature_extractor import FEATURE_NAMES, features_to_vector, normalize_request

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "attack_detection_model.pkl")
ATTACK_TYPES = ["NORMAL", "SQL_INJECTION", "XSS", "BRUTE_FORCE", "API_ABUSE"]
MALICIOUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 30

_bundle = None


def load_model(path: str = MODEL_PATH, reload: bool = False):
    """Load (and cache) the trained model; train it automatically if missing."""
    global _bundle
    if _bundle is None or reload:
        if not os.path.exists(path):
            from .train_model import train
            train(save=True, verbose=False)
        _bundle = joblib.load(path)
    return _bundle


def risk_level(score: int) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "MALICIOUS"
    return "SUSPICIOUS" if score >= SUSPICIOUS_THRESHOLD else "NORMAL"


def detect_attack(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Classify one gateway request. Stateless: behavioural counters
    (request_count, failed_attempts, ...) are read from the request if present;
    use RequestTracker / Detector to have them computed from traffic history."""
    b = load_model()
    clf = b["model"]
    vec = pd.DataFrame([features_to_vector(request_data)], columns=FEATURE_NAMES)
    proba = clf.predict_proba(vec)[0]
    classes = list(clf.classes_)
    best = max(range(len(classes)), key=lambda i: proba[i])
    label = classes[best]
    p_normal = float(proba[classes.index("NORMAL")]) if "NORMAL" in classes else 0.0
    score = max(0, min(100, int(round(100 * (1.0 - p_normal)))))
    return {
        "attack_type": label,
        "confidence": round(float(proba[best]), 4),
        "risk_score": score,
        "is_malicious": bool(label != "NORMAL" and score >= MALICIOUS_THRESHOLD),
        "risk_level": risk_level(score),
        "probabilities": {c: round(float(p), 4) for c, p in zip(classes, proba)},
    }


class RequestTracker:
    """Per-IP sliding window (default 60 s) that derives the behavioural features
    the gateway may not provide: request_count, repeated_requests, failed_attempts,
    unique_endpoints."""

    def __init__(self, window_seconds: float = 60.0):
        self.window = window_seconds
        self._events = defaultdict(deque)  # ip -> deque[(t, endpoint, failed)]

    def update(self, request_data: Dict[str, Any], now: float = None) -> Dict[str, Any]:
        r = normalize_request(request_data)
        now = time.time() if now is None else now
        q = self._events[r["ip"]]
        q.append((now, r["endpoint"], r["status_code"] in (401, 403)))
        while q and now - q[0][0] > self.window:
            q.popleft()
        enriched = dict(request_data)
        enriched.update(
            request_count=len(q),
            repeated_requests=sum(1 for e in q if e[1] == r["endpoint"]) - 1,
            failed_attempts=sum(1 for e in q if e[2]),
            unique_endpoints=len({e[1] for e in q}),
        )
        return enriched


class Detector:
    """Stateful wrapper for live use by the gateway: tracks history per IP."""

    def __init__(self, window_seconds: float = 60.0):
        self.tracker = RequestTracker(window_seconds)

    def inspect(self, request_data: Dict[str, Any], now: float = None) -> Dict[str, Any]:
        return detect_attack(self.tracker.update(request_data, now))
