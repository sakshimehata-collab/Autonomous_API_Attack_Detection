import json
from datetime import datetime, timezone


def capture_request(request):
    """Capture important details from an API request."""

    request_data = {
        "ip": request.remote_addr,
        "method": request.method,
        "endpoint": request.path,
        "headers": {
            "content_type": request.content_type
        },
        "payload": request.get_json(silent=True)
                    or request.form.to_dict(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    return request_data


def save_request(request_data):
    """Save captured requests to a JSON Lines file."""

    with open("request_logs.jsonl", "a", encoding="utf-8") as file:
        file.write(json.dumps(request_data) + "\n")