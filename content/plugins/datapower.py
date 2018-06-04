import re

from lib.settings import HTTP_HEADER


__product__ = "IBM Websphere DataPower Firewall (IBM)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"\A(ok|fail)", re.I),
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.X_BACKSIDE_TRANS, "")) is not None:
            return True
