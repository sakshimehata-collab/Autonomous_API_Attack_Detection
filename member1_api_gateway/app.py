from flask import Flask, request, jsonify
from request_logger import capture_request , save_request
from detection_client import send_to_detector
from datetime import datetime, timezone


app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Autonomous API Attack Detection System",
        "status": "API Gateway is running"
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "health"

    })

@app.route("/inspect", methods=["GET", "POST"])
def inspect():
    request_data = capture_request(request)

    save_request(request_data)

    print("Captured Request:")
    print(request_data)

    return jsonify({
        "message": "Request captured successfully",
        "request": request_data
    }), 200

@app.route("/analyze", methods=["POST"])
def analyze():
    request_data = capture_request(request)

    detection_result = send_to_detector(request_data)

    return jsonify({
        "request": request_data,
        "detection": detection_result
    }), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)