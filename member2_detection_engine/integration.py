"""Glue between Member 1's gateway and Member 2's detector.

Member 1 only needs ONE of:
    from member2_detection_engine.integration import inspect_request
    verdict = inspect_request(request_dict)          # stateful, tracks per-IP history

Whatever fields the gateway captured (ip/client_ip, method, endpoint/path,
payload/body/params, status_code ...) are mapped by feature_extractor.normalize_request.
"""
from typing import Any, Dict

from .detector import Detector

_detector = Detector()


def inspect_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Return the detection verdict merged with the original request metadata."""
    verdict = _detector.inspect(request_data)
    return {"ip": request_data.get("ip") or request_data.get("client_ip") or request_data.get("remote_addr"),
            **verdict}
