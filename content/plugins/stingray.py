import re

from lib.settings import HTTP_HEADER


__product__ = "Stingray Application Firewall (Riverbed / Brocade)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    status = kwargs.get("status", None)
    status_schema = (403, 500)
    detection_schema = (
        re.compile(r"\AX-Mapping-", re.I),
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None:
            if status in status_schema:
                return True