"""
Member 4 - Attack Simulator

Sends harmless synthetic requests through the complete
Member 2 -> Member 4 pipeline for testing and demonstration.
"""

import json

from .integration import process_request


TEST_REQUESTS = [
    {
        "name": "NORMAL REQUEST",
        "request": {
            "ip": "192.168.1.20",
            "method": "POST",
            "endpoint": "/login",
            "payload": "username=alice&password=Pass123",
        },
    },
    {
        "name": "SQL INJECTION",
        "request": {
            "ip": "192.168.1.21",
            "method": "POST",
            "endpoint": "/login",
            "payload": "username=admin' OR '1'='1' --&password=x",
        },
    },
    {
        "name": "XSS",
        "request": {
            "ip": "192.168.1.22",
            "method": "POST",
            "endpoint": "/comments",
            "payload": "comment=<script>alert(1)</script>",
        },
    },
]


def run_simulation():
    """Run all synthetic test requests."""

    print("=" * 60)
    print("AUTONOMOUS API ATTACK DETECTION - MEMBER 4 TEST")
    print("=" * 60)

    for test in TEST_REQUESTS:
        print(f"\n--- {test['name']} ---")

        result = process_request(test["request"])

        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    run_simulation()