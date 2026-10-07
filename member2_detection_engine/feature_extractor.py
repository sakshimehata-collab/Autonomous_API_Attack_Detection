"""Feature extraction for Member 2 (deterministic, no randomness, no I/O).

Two layers:
  1. normalize_request(): adapts whatever the gateway (Member 1) captured into
     one canonical dict.  Several common field names are accepted so the
     module keeps working if Member 1 names things differently.
  2. extract_features(): turns the canonical request into a numeric vector.

Regex/keyword matches are used ONLY as numeric features; the class decision is
made by the trained RandomForest.
"""
import json
import re
from typing import Any, Dict, List
from urllib.parse import unquote_plus

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

# ---- field-name aliases (adapter) -----------------------------------------
_ALIASES = {
    "ip": ["ip", "client_ip", "remote_addr", "source_ip", "src_ip"],
    "method": ["method", "http_method", "verb"],
    "endpoint": ["endpoint", "path", "url", "route", "uri"],
    "payload": ["payload", "body", "data", "json", "params", "query", "query_params", "form"],
    "status_code": ["status_code", "status", "response_status", "response_code"],
    # optional behavioural counters (window = last 60 s per IP)
    "request_count": ["request_count", "requests_last_minute", "request_frequency", "req_per_min"],
    "failed_attempts": ["failed_attempts", "failed_logins", "failed_count"],
    "repeated_requests": ["repeated_requests", "repeat_count", "same_endpoint_count"],
    "unique_endpoints": ["unique_endpoints", "distinct_endpoints"],
}

_SQL_KEYWORDS = ["select", "union", "insert", "update", "delete", "drop", "from", "where",
                 "or", "and", "sleep", "benchmark", "having", "order by", "group by",
                 "information_schema", "exec", "like"]
_SQL_PATTERNS = [
    r"('|%27)\s*(or|and)\s+['\"\d\w]",           # ' OR 1...
    r"\b(or|and)\b\s+\d+\s*=\s*\d+",             # OR 1=1
    r"\bunion\b\s+(all\s+)?\bselect\b",
    r"(--|#|/\*)\s*\w*\s*$",                     # trailing comment
    r";\s*(drop|delete|update|insert)\b",
    r"\b(sleep|benchmark|waitfor)\s*\(",
    r"\binformation_schema\b",
]
_XSS_PATTERNS = [
    r"<\s*/?\s*script", r"<\s*(img|svg|iframe|body|input|a)\b[^>]*>",
    r"\bon\w+\s*=", r"javascript\s*:", r"\balert\s*\(", r"document\.(cookie|location|write)",
    r"<\s*[a-z]+[^>]*>", r"&lt;|&#x?3c;",
]
_SPECIAL = set("!@#$%^&*()+=[]{};:'\"<>?/\\|`~,")
_SUSPICIOUS = set("'\"<>;()=-/\\%#`|")
_ENCODING_RE = re.compile(r"%[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")

FEATURE_NAMES: List[str] = (
    ["method_" + m for m in METHODS]
    + ["endpoint_length", "endpoint_depth", "is_auth_endpoint", "payload_length",
       "special_char_count", "special_char_ratio", "suspicious_char_count",
       "sql_keyword_count", "sql_pattern_count", "has_sql_comment",
       "tag_count", "xss_pattern_count", "event_handler_count",
       "encoding_count", "encoded_ratio", "param_count", "digit_ratio",
       "upper_ratio", "suspicious_pattern_count",
       "request_count", "failed_attempts", "repeated_requests",
       "unique_endpoints", "is_error_status"]
)


def _first(req: Dict[str, Any], key: str, default=None):
    for name in _ALIASES[key]:
        if name in req and req[name] is not None:
            return req[name]
    return default


def _stringify(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, (dict, list)):
        return json.dumps(payload, sort_keys=True)
    if isinstance(payload, bytes):
        return payload.decode("utf-8", "replace")
    return str(payload)


def _num(v, default=0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return float(default)


def normalize_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Map a gateway request dict to the canonical schema."""
    if not isinstance(request_data, dict):
        raise TypeError("request_data must be a dict")
    payload = _first(request_data, "payload", "")
    # a query string embedded in the endpoint also counts as payload
    endpoint = str(_first(request_data, "endpoint", "/") or "/")
    if "?" in endpoint:
        endpoint, qs = endpoint.split("?", 1)
        payload = _stringify(payload) + ("&" if payload else "") + qs
    return {
        "ip": str(_first(request_data, "ip", "unknown")),
        "method": str(_first(request_data, "method", "GET")).upper(),
        "endpoint": endpoint,
        "payload": _stringify(payload),
        "status_code": int(_num(_first(request_data, "status_code", 0))),
        "request_count": _num(_first(request_data, "request_count", 0)),
        "failed_attempts": _num(_first(request_data, "failed_attempts", 0)),
        "repeated_requests": _num(_first(request_data, "repeated_requests", 0)),
        "unique_endpoints": _num(_first(request_data, "unique_endpoints", 0)),
    }


def extract_features(request_data: Dict[str, Any]) -> Dict[str, float]:
    """Return an ordered dict {feature_name: value} (keys == FEATURE_NAMES)."""
    r = normalize_request(request_data)
    raw = r["payload"]
    decoded = unquote_plus(raw)              # look through URL-encoding
    text = (raw + " " + decoded).lower()
    n = len(raw)

    f: Dict[str, float] = {}
    for m in METHODS:
        f["method_" + m] = 1.0 if r["method"] == m else 0.0
    ep = r["endpoint"]
    f["endpoint_length"] = len(ep)
    f["endpoint_depth"] = len([p for p in ep.split("/") if p])
    f["is_auth_endpoint"] = 1.0 if re.search(r"login|signin|auth|token|password|session", ep, re.I) else 0.0
    f["payload_length"] = n
    specials = sum(1 for c in raw if c in _SPECIAL)
    f["special_char_count"] = specials
    f["special_char_ratio"] = specials / n if n else 0.0
    f["suspicious_char_count"] = sum(1 for c in decoded if c in _SUSPICIOUS)
    f["sql_keyword_count"] = sum(len(re.findall(r"\b" + re.escape(k) + r"\b", text)) for k in _SQL_KEYWORDS)
    sql_pat = sum(1 for p in _SQL_PATTERNS if re.search(p, text, re.I))
    f["sql_pattern_count"] = sql_pat
    f["has_sql_comment"] = 1.0 if re.search(r"(--\s|--$|#|/\*)", decoded) else 0.0
    f["tag_count"] = len(re.findall(r"<[^>]*>?", decoded))
    xss_pat = sum(1 for p in _XSS_PATTERNS if re.search(p, text, re.I))
    f["xss_pattern_count"] = xss_pat
    f["event_handler_count"] = len(re.findall(r"\bon[a-z]+\s*=", text))
    enc = len(_ENCODING_RE.findall(raw))
    f["encoding_count"] = enc
    f["encoded_ratio"] = (enc * 3) / n if n else 0.0
    f["param_count"] = len([p for p in re.split(r"[&;]", raw) if "=" in p]) if raw and not raw.lstrip().startswith("{") \
        else (len(json.loads(raw)) if raw.lstrip().startswith("{") and _is_json(raw) else 0)
    f["digit_ratio"] = sum(c.isdigit() for c in raw) / n if n else 0.0
    f["upper_ratio"] = sum(c.isupper() for c in raw) / n if n else 0.0
    f["suspicious_pattern_count"] = sql_pat + xss_pat + (1 if enc > 2 else 0)
    f["request_count"] = r["request_count"]
    f["failed_attempts"] = r["failed_attempts"]
    f["repeated_requests"] = r["repeated_requests"]
    f["unique_endpoints"] = r["unique_endpoints"]
    f["is_error_status"] = 1.0 if r["status_code"] >= 400 else 0.0
    return {k: float(f[k]) for k in FEATURE_NAMES}


def _is_json(s: str) -> bool:
    try:
        return isinstance(json.loads(s), dict)
    except ValueError:
        return False


def features_to_vector(request_data: Dict[str, Any]) -> List[float]:
    feats = extract_features(request_data)
    return [feats[k] for k in FEATURE_NAMES]
