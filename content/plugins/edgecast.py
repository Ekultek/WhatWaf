import re

from lib.settings import HTTP_HEADER


__product__ = "EdgeCast Web Application Firewall (Verizon)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"\Aecdf", re.I),
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
