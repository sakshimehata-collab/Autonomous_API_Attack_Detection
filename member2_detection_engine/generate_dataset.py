"""Generate the synthetic training dataset (dataset.csv).

All strings are harmless, textbook-style samples against made-up endpoints.
Rows hold RAW request fields; features are extracted later in train_model.py
(so the model learns from derived features, not from stored labels-by-rule).
Deterministic: fixed seed.
"""
import csv
import os
import random

SEED = 42
HERE = os.path.dirname(os.path.abspath(__file__))
rnd = random.Random(SEED)

NAMES = ["alice", "bob", "carol", "dave", "erin", "O'Brien", "d'souza", "priya", "rahul", "meera", "li wei"]
WORDS = ["laptop", "red shoes", "select a plan", "update profile", "order from store", "delete my draft",
         "where is my order", "union station map", "drop off point", "insert coin game", "and or not", "books"]
COLS = ["ip", "method", "endpoint", "payload", "request_count", "failed_attempts",
        "repeated_requests", "unique_endpoints", "status_code", "label"]


def ip():
    return "10.%d.%d.%d" % (rnd.randint(0, 255), rnd.randint(0, 255), rnd.randint(2, 250))


def mix(base_requests=(1, 12)):
    """benign behavioural counters"""
    return dict(request_count=rnd.randint(*base_requests), failed_attempts=rnd.choice([0, 0, 0, 1]),
                repeated_requests=rnd.randint(0, 3), unique_endpoints=rnd.randint(1, 5), status_code=200)


def normal():
    k = rnd.choice(["login", "search", "profile", "order", "json", "list", "note"])
    if k == "login":
        m, e, p = "POST", "/login", "username=%s&password=Pass%d" % (rnd.choice(NAMES), rnd.randint(100, 999))
    elif k == "search":
        m, e, p = "GET", "/search", "q=%s&page=%d" % (rnd.choice(WORDS), rnd.randint(1, 9))
    elif k == "profile":
        m, e, p = rnd.choice(["GET", "PUT"]), "/users/%d" % rnd.randint(1, 500), \
            "" if rnd.random() < .5 else "name=%s&city=Pune" % rnd.choice(NAMES)
    elif k == "order":
        m, e, p = "POST", "/orders", "item=%s&qty=%d" % (rnd.choice(WORDS), rnd.randint(1, 5))
    elif k == "json":
        m, e, p = "POST", "/api/items", '{"title": "%s", "price": %d}' % (rnd.choice(WORDS), rnd.randint(5, 500))
    elif k == "list":
        m, e, p = "GET", "/products", "category=%s&limit=%d" % (rnd.choice(WORDS), rnd.choice([10, 20, 50]))
    else:
        m, e, p = "POST", "/notes", "text=Meeting at %d:00 - bring <laptop> & notes (ok)" % rnd.randint(9, 17) \
            if rnd.random() < .25 else "text=Meeting at %d pm" % rnd.randint(1, 8)
    return dict(ip=ip(), method=m, endpoint=e, payload=p, **mix())


SQL = ["' OR '1'='1", "' OR 1=1 --", "admin' --", "1' UNION SELECT username, password FROM users --",
       "1 UNION ALL SELECT null,null,null--", "'; DROP TABLE demo_users; --", "1' AND SLEEP(5) --",
       "' OR 'a'='a' #", "x' AND 1=1 UNION SELECT table_name FROM information_schema.tables --",
       "%27%20OR%20%271%27%3D%271", "1; DELETE FROM sample_items WHERE 1=1", "' HAVING 1=1 --",
       "1' ORDER BY 3 --", "\" OR \"\"=\"", "admin') OR ('1'='1", "id=1' AND BENCHMARK(100,MD5(1)) --"]
XSS = ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
       "<iframe src=javascript:alert(1)></iframe>", "\"><script>alert(document.cookie)</script>",
       "<body onload=alert('test')>", "<a href=\"javascript:alert(1)\">click</a>",
       "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "<input onfocus=alert(1) autofocus>",
       "&lt;script&gt;alert(1)&lt;/script&gt;", "<ScRiPt>alert(String.fromCharCode(88))</ScRiPt>",
       "<div onmouseover=\"alert(1)\">hover</div>", "javascript:alert('demo')"]
FIELDS = ["username", "q", "comment", "name", "id", "search", "title", "email"]
ENDPOINTS = ["/login", "/search", "/comments", "/users/profile", "/products", "/feedback", "/api/items"]


def injected(pool):
    f, pay = rnd.choice(FIELDS), rnd.choice(pool)
    p = "%s=%s" % (f, pay)
    if rnd.random() < .35:
        p = "page=%d&%s" % (rnd.randint(1, 5), p)
    if rnd.random() < .15:
        p = '{"%s": "%s"}' % (f, pay.replace('"', "'"))
    return dict(ip=ip(), method=rnd.choice(["GET", "POST", "POST"]), endpoint=rnd.choice(ENDPOINTS),
                payload=p, **mix())


def brute():
    n = rnd.randint(8, 60)
    return dict(ip=ip(), method="POST", endpoint=rnd.choice(["/login", "/api/auth", "/signin", "/token"]),
                payload="username=%s&password=guess%d" % (rnd.choice(["admin", "root", "test", "user1"]), rnd.randint(1, 9999)),
                request_count=rnd.randint(n, n + 40), failed_attempts=rnd.randint(max(5, n // 2), n + 10),
                repeated_requests=rnd.randint(n // 2, n + 20), unique_endpoints=rnd.randint(1, 2), status_code=401)


def abuse():
    kind = rnd.choice(["flood", "scrape", "enum", "bulk"])
    if kind == "flood":
        return dict(ip=ip(), method="GET", endpoint=rnd.choice(["/products", "/search", "/api/items"]),
                    payload="q=%s&page=%d" % (rnd.choice(WORDS), rnd.randint(1, 5)),
                    request_count=rnd.randint(150, 900), failed_attempts=rnd.choice([0, 0, 2]),
                    repeated_requests=rnd.randint(100, 800), unique_endpoints=rnd.randint(1, 3), status_code=rnd.choice([200, 429]))
    if kind == "scrape":
        return dict(ip=ip(), method="GET", endpoint="/users/%d" % rnd.randint(1, 99999), payload="",
                    request_count=rnd.randint(100, 600), failed_attempts=0, repeated_requests=rnd.randint(5, 40),
                    unique_endpoints=rnd.randint(40, 300), status_code=200)
    if kind == "enum":
        return dict(ip=ip(), method=rnd.choice(["GET", "DELETE"]), endpoint="/api/v1/admin/%s" % rnd.choice(["users", "config", "export", "keys"]),
                    payload="", request_count=rnd.randint(80, 400), failed_attempts=rnd.randint(30, 200),
                    repeated_requests=rnd.randint(3, 30), unique_endpoints=rnd.randint(30, 200), status_code=rnd.choice([403, 404]))
    big = "data=" + "A" * rnd.randint(2000, 6000)
    return dict(ip=ip(), method="POST", endpoint="/api/items", payload=big,
                request_count=rnd.randint(100, 500), failed_attempts=0, repeated_requests=rnd.randint(50, 300),
                unique_endpoints=rnd.randint(1, 4), status_code=rnd.choice([200, 413]))


def main(per_class=500):
    rows = []
    for _ in range(per_class):
        rows.append({**normal(), "label": "NORMAL"})
        rows.append({**injected(SQL), "label": "SQL_INJECTION"})
        rows.append({**injected(XSS), "label": "XSS"})
        rows.append({**brute(), "label": "BRUTE_FORCE"})
        rows.append({**abuse(), "label": "API_ABUSE"})
    rnd.shuffle(rows)
    path = os.path.join(HERE, "dataset.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)
    print("wrote %d rows -> %s" % (len(rows), path))


if __name__ == "__main__":
    main()
