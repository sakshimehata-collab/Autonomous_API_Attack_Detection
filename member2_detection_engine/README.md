# Member 2 — AI/ML Attack Detection Engine

Classifies each API request captured by Member 1's gateway as one of
`NORMAL`, `SQL_INJECTION`, `XSS`, `BRUTE_FORCE`, `API_ABUSE`, with a confidence and a 0–100 risk score.
Defensive use only; all training data is synthetic and harmless.

## Architecture
```
Member 1 API Gateway
      │  request dict {ip, method, endpoint, payload, [status_code]}
      ▼
integration.inspect_request()  ──►  RequestTracker (per-IP 60 s window:
      │                              request_count, repeated_requests,
      ▼                              failed_attempts, unique_endpoints)
feature_extractor.extract_features()   (25 numeric features)
      ▼
RandomForestClassifier  (model/attack_detection_model.pkl)
      ▼
predict_proba ─► attack_type, confidence, risk_score
      ▼
JSON verdict  ──►  Member 3 / Member 4
```

## Input
A dict. Accepted names (first match wins): `ip|client_ip|remote_addr`, `method|http_method`,
`endpoint|path|url`, `payload|body|data|json|params|query`, optional `status_code`.
A `?query` in the endpoint is treated as payload. Optional behavioural counters
(`request_count`, `failed_attempts`, `repeated_requests`, `unique_endpoints`) are used if supplied.

## Features (`feature_extractor.py`, deterministic)
HTTP method (one-hot) · endpoint length/depth/is-auth-endpoint · payload length · special-char count & ratio ·
suspicious-char count · SQL keyword count · SQL pattern count · SQL comment flag · tag count · XSS pattern count ·
event-handler count · encoding count & ratio · parameter count · digit/upper ratios · suspicious-pattern total ·
request count · failed attempts · repeated requests · unique endpoints · error-status flag.
Rules only produce numbers; the **class is decided by the trained model**.

## Dataset
`generate_dataset.py` (seed 42) → `dataset.csv`: 2 500 raw rows, 500 per class. Rows contain raw request fields;
features are derived at training time. NORMAL rows deliberately include apostrophes (`O'Brien`), SQL words
("select a plan"), and tags/symbols in notes so the model cannot rely on a single keyword.

## Training
`RandomForestClassifier(n_estimators=200, max_depth=14, class_weight="balanced", random_state=42)`,
stratified 80/20 split done before fitting; prints accuracy, weighted precision/recall/F1, per-class report,
confusion matrix; saves `model/attack_detection_model.pkl`.

## Risk score
```
p_mal      = 1 - P(NORMAL)          (RandomForest predict_proba)
risk_score = round(100 * p_mal)
0-29 NORMAL | 30-69 SUSPICIOUS | 70-100 MALICIOUS
is_malicious = predicted class != NORMAL and risk_score >= 70
confidence   = predict_proba of the predicted class (0..1)
```

## Output
```json
{"attack_type": "SQL_INJECTION", "confidence": 0.8894, "risk_score": 90, "is_malicious": true,
 "risk_level": "MALICIOUS", "probabilities": {"NORMAL": 0.1006, "SQL_INJECTION": 0.8894, "...": 0.0}}
```

## How Member 1 integrates
```python
from member2_detection_engine.integration import inspect_request
verdict = inspect_request(request_dict)       # call once per incoming request, e.g. in middleware
if verdict["is_malicious"]: ...               # block / log / alert
```
Stateless alternative: `from member2_detection_engine import detect_attack`.
(Behavioural attacks – brute force / abuse – need the stateful `inspect_request`/`Detector`, which remembers
recent requests per IP. Pass `status_code` (401/403 on failed logins) for best brute-force detection.)

## Commands (run from repository root)
```
pip install -r member2_detection_engine/requirements.txt
python -m member2_detection_engine.generate_dataset     # optional: regenerate dataset
python -m member2_detection_engine.train_model
python -m pytest member2_detection_engine/tests -v      # or: python -m unittest discover -s member2_detection_engine/tests -t .
python -m member2_detection_engine.predict              # demo of all 5 classes
```

## Limitations
The dataset is synthetic and template-based, so near-perfect test scores are expected and do not predict
real-world accuracy. For a stronger evaluation, add real/benchmark traffic (e.g. CSIC 2010) to `dataset.csv`.
