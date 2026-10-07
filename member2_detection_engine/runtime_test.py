from member2_detection_engine.integration import inspect_request


def show(name, result):
    print("-" * 75)
    print(name)
    print(f"Predicted  : {result['attack_type']}")
    print(f"Confidence : {result['confidence']}")
    print(f"Risk Score : {result['risk_score']}")
    print(f"Malicious  : {result['is_malicious']}")
    print(f"Risk Level : {result['risk_level']}")


print("=" * 75)
print("       MEMBER 2 STATEFUL RUNTIME TEST")
print("=" * 75)


# ============================================================
# 1. NORMAL
# ============================================================

result = inspect_request({
    "ip": "10.1.0.1",
    "method": "GET",
    "endpoint": "/products",
    "payload": "category=shoes&page=2"
})
show("NORMAL", result)


# ============================================================
# 2. SQL INJECTION
# ============================================================

result = inspect_request({
    "ip": "10.1.0.2",
    "method": "POST",
    "endpoint": "/user/search",
    "payload": "id=5 UNION SELECT username,password FROM users"
})
show("SQL INJECTION", result)


# ============================================================
# 3. XSS
# ============================================================

result = inspect_request({
    "ip": "10.1.0.3",
    "method": "POST",
    "endpoint": "/comments",
    "payload": "<svg onload=alert(document.domain)>"
})
show("XSS", result)


# ============================================================
# 4. BRUTE FORCE
# Same IP + repeated failed login attempts
# ============================================================

print("-" * 75)
print("BRUTE FORCE SEQUENCE")

for i in range(8):
    result = inspect_request({
        "ip": "10.1.0.4",
        "method": "POST",
        "endpoint": "/login",
        "payload": f"username=admin&password=wrong{i}",
        "status_code": 401
    })

print(f"Requests sent: 8")
print(f"Predicted    : {result['attack_type']}")
print(f"Confidence   : {result['confidence']}")
print(f"Risk Score   : {result['risk_score']}")
print(f"Malicious    : {result['is_malicious']}")
print(f"Risk Level   : {result['risk_level']}")


# ============================================================
# 5. API ABUSE
# Same IP + repeated requests to API
# ============================================================

print("-" * 75)
print("API ABUSE SEQUENCE")

for i in range(12):
    result = inspect_request({
        "ip": "10.1.0.5",
        "method": "GET",
        "endpoint": "/api/users",
        "payload": f"page={i}&limit=10000",
        "status_code": 200
    })

print(f"Requests sent: 12")
print(f"Predicted    : {result['attack_type']}")
print(f"Confidence   : {result['confidence']}")
print(f"Risk Score   : {result['risk_score']}")
print(f"Malicious    : {result['is_malicious']}")
print(f"Risk Level   : {result['risk_level']}")


print()
print("=" * 75)
print("STATEFUL TEST COMPLETE")
print("=" * 75)