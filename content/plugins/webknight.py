import re

from lib.settings import HTTP_HEADER


__product__ = "WebKnight Application Firewall (AQTRONIX)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    status = kwargs.get("status", None)
    detection_schema = (
        re.compile(r"\bwebknight", re.I),
        re.compile(r"webknight", re.I)
    )
    if status is not None:
        if status == 999 and headers.get(HTTP_HEADER.SERVER, "") == "WebKnight":
            return True
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
