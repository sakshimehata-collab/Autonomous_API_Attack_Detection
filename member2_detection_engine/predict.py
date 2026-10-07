"""CLI demo.   python -m member2_detection_engine.predict"""
import json
import sys

from .detector import Detector, detect_attack

DEMO = [
    ("NORMAL", {"ip": "192.168.1.20", "method": "POST", "endpoint": "/login", "payload": "username=alice&password=Pass123"}),
    ("SQL_INJECTION", {"ip": "192.168.1.21", "method": "POST", "endpoint": "/login", "payload": "username=admin' OR '1'='1' --&password=x"}),
    ("XSS", {"ip": "192.168.1.22", "method": "POST", "endpoint": "/comments", "payload": "comment=<script>alert('xss')</script>"}),
]


def main():
    if len(sys.argv) > 1:  # python -m ... predict '{"method":"GET",...}'
        print(json.dumps(detect_attack(json.loads(sys.argv[1])), indent=2))
        return
    for name, req in DEMO:
        print("== expected %s\n   input : %s\n   output: %s" % (name, json.dumps(req), json.dumps(detect_attack(req))))
    # behavioural attacks: feed the stateful Detector with a simulated burst (documentation IPs only)
    det = Detector()
    for label, ip, ep, pay, st, n in [("BRUTE_FORCE", "203.0.113.5", "/login", "username=admin&password=guess1", 401, 30),
                                      ("API_ABUSE", "203.0.113.9", "/products", "q=shoes&page=1", 200, 400)]:
        res = None
        for i in range(n):
            res = det.inspect({"ip": ip, "method": "POST" if label == "BRUTE_FORCE" else "GET", "endpoint": ep,
                               "payload": pay, "status_code": st}, now=1000.0 + i * 0.1)
        print("== expected %s (after %d requests from one IP)\n   output: %s" % (label, n, json.dumps(res)))


if __name__ == "__main__":
    main()
