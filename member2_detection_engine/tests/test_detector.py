import os
import unittest

from member2_detection_engine import Detector, detect_attack
from member2_detection_engine.detector import ATTACK_TYPES, MODEL_PATH, load_model
from member2_detection_engine.integration import inspect_request

KEYS = {"attack_type", "confidence", "risk_score", "is_malicious"}


def burst(det, ip, method, ep, payload, status, n):
    res = None
    for i in range(n):
        res = det.inspect({"ip": ip, "method": method, "endpoint": ep, "payload": payload, "status_code": status},
                          now=100.0 + i * 0.1)
    return res


class TestDetector(unittest.TestCase):
    def check_schema(self, r):
        self.assertTrue(KEYS <= set(r))
        self.assertIn(r["attack_type"], ATTACK_TYPES)
        self.assertTrue(0 <= r["confidence"] <= 1)
        self.assertTrue(0 <= r["risk_score"] <= 100)
        self.assertIsInstance(r["is_malicious"], bool)

    def test_model_file_exists_and_loads(self):
        load_model()
        self.assertTrue(os.path.exists(MODEL_PATH))

    def test_normal(self):
        r = detect_attack({"ip": "10.0.0.5", "method": "POST", "endpoint": "/login", "payload": "username=alice&password=Pass123"})
        self.check_schema(r)
        self.assertEqual(r["attack_type"], "NORMAL")
        self.assertFalse(r["is_malicious"])
        self.assertLess(r["risk_score"], 30)

    def test_normal_with_apostrophe_and_sql_words(self):
        r = detect_attack({"method": "GET", "endpoint": "/search", "payload": "q=select a plan for O'Brien"})
        self.assertEqual(r["attack_type"], "NORMAL")

    def test_sql_injection(self):
        r = detect_attack({"ip": "10.0.0.6", "method": "POST", "endpoint": "/login", "payload": "username=admin' OR '1'='1' --&password=x"})
        self.check_schema(r)
        self.assertEqual(r["attack_type"], "SQL_INJECTION")
        self.assertTrue(r["is_malicious"])
        self.assertGreaterEqual(r["risk_score"], 70)

    def test_sql_injection_url_encoded(self):
        r = detect_attack({"method": "GET", "endpoint": "/search", "payload": "q=%27%3B%20DROP%20TABLE%20x%3B--"})
        self.assertEqual(r["attack_type"], "SQL_INJECTION")

    def test_xss(self):
        r = detect_attack({"ip": "10.0.0.7", "method": "POST", "endpoint": "/comments", "payload": "comment=<script>alert('xss')</script>"})
        self.check_schema(r)
        self.assertEqual(r["attack_type"], "XSS")
        self.assertTrue(r["is_malicious"])

    def test_xss_event_handler(self):
        r = detect_attack({"method": "POST", "endpoint": "/profile", "payload": "bio=<img src=1 onerror=prompt(1)>"})
        self.assertEqual(r["attack_type"], "XSS")

    def test_brute_force_behaviour(self):
        r = burst(Detector(), "203.0.113.5", "POST", "/login", "username=admin&password=guess1", 401, 30)
        self.check_schema(r)
        self.assertEqual(r["attack_type"], "BRUTE_FORCE")
        self.assertTrue(r["is_malicious"])

    def test_api_abuse_behaviour(self):
        r = burst(Detector(), "203.0.113.9", "GET", "/products", "q=shoes&page=1", 200, 400)
        self.check_schema(r)
        self.assertEqual(r["attack_type"], "API_ABUSE")
        self.assertTrue(r["is_malicious"])

    def test_single_request_stays_normal_in_stateful_detector(self):
        r = Detector().inspect({"ip": "10.1.1.1", "method": "GET", "endpoint": "/products", "payload": "q=shoes"})
        self.assertEqual(r["attack_type"], "NORMAL")

    def test_ip_isolation(self):
        det = Detector()
        burst(det, "203.0.113.5", "POST", "/login", "u=a&p=b", 401, 30)
        r = det.inspect({"ip": "10.9.9.9", "method": "POST", "endpoint": "/login", "payload": "username=bob&password=Pass1"}, now=200.0)
        self.assertEqual(r["attack_type"], "NORMAL")

    def test_ranges_over_many_inputs(self):
        for p in ["", "x" * 5000, "<<<>>>'''---", "a=1&b=2&c=3", "%00%00%00", '{"a": {"b": 1}}']:
            self.check_schema(detect_attack({"method": "POST", "endpoint": "/x", "payload": p}))

    def test_bad_input_type(self):
        with self.assertRaises(TypeError):
            detect_attack("not a dict")


class TestIntegration(unittest.TestCase):
    """Simulated Member 1 gateway requests -> Member 2 -> verdict JSON.
    Field names follow the common gateway shape; the adapter also accepts aliases."""

    def test_gateway_request_to_verdict(self):
        gateway_request = {"client_ip": "192.168.1.30", "method": "POST", "path": "/login",
                           "body": "username=admin' OR 1=1 --&password=x", "status_code": 200}
        v = inspect_request(gateway_request)
        self.assertEqual(v["ip"], "192.168.1.30")
        self.assertEqual(v["attack_type"], "SQL_INJECTION")
        self.assertTrue(KEYS <= set(v))

    def test_dict_body_and_query_string_endpoint(self):
        v = inspect_request({"ip": "192.168.1.31", "method": "GET", "endpoint": "/search?q=<script>alert(1)</script>"})
        self.assertEqual(v["attack_type"], "XSS")


if __name__ == "__main__":
    unittest.main()
