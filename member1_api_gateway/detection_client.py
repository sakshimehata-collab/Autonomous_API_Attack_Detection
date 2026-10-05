import requests

DETECTION_URL = "http://127.0.0.1:8000/predict"


def send_to_detector(request_data):
    try:
        response = requests.post(
            DETECTION_URL,
            json=request_data,
            timeout=5
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }