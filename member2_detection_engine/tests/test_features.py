import unittest

from member2_detection_engine.feature_extractor import (FEATURE_NAMES, extract_features, normalize_request)


class TestFeatures(unittest.TestCase):
    def test_keys_and_determinism(self):
        r = {"ip": "1.1.1.1", "method": "POST", "endpoint": "/login", "payload": "u=a' OR 1=1 --"}
        a, b = extract_features(r), extract_features(r)
        self.assertEqual(list(a), FEATURE_NAMES)
        self.assertEqual(a, b)

    def test_sql_signals(self):
        f = extract_features({"method": "GET", "endpoint": "/s", "payload": "q=1' UNION SELECT a FROM t --"})
        self.assertGreater(f["sql_keyword_count"], 2)
        self.assertGreater(f["sql_pattern_count"], 0)
        self.assertEqual(f["has_sql_comment"], 1.0)

    def test_xss_and_encoding_signals(self):
        f = extract_features({"method": "GET", "endpoint": "/s", "payload": "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"})
        self.assertGreater(f["xss_pattern_count"], 0)
        self.assertGreater(f["encoding_count"], 0)
        self.assertGreater(f["tag_count"], 0)

    def test_benign_has_few_signals(self):
        f = extract_features({"method": "GET", "endpoint": "/search", "payload": "q=red shoes&page=2"})
        self.assertEqual(f["suspicious_pattern_count"], 0)
        self.assertEqual(f["param_count"], 2)

    def test_aliases_and_query_string(self):
        r = normalize_request({"client_ip": "9.9.9.9", "http_method": "get", "path": "/x?a=1&b=2", "body": {"k": "v"}})
        self.assertEqual((r["ip"], r["method"], r["endpoint"]), ("9.9.9.9", "GET", "/x"))
        self.assertIn("a=1", r["payload"])

    def test_empty_payload(self):
        f = extract_features({"method": "GET", "endpoint": "/"})
        self.assertEqual(f["payload_length"], 0)


if __name__ == "__main__":
    unittest.main()
