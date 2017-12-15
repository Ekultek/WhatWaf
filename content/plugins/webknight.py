import re

from lib.settings import HTTP_HEADER


__product__ = "WebKnight Application Firewall (AQTRONIX)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    status = kwargs.get("status", None)
    detection_schema = (
        re.compile(r"webknight", re.I),
        re.compile(r"WebKnight", re.I)
    )
    if status is not None:
        if status == 999:
            return True
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
