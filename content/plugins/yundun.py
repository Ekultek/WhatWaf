import re

from lib.settings import HTTP_HEADER


__product__ = "Yundun Web Application Firewall (Yundun)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"YUNDUN", re.I),
    )
    if headers is not None:
        for detection in detection_schema:
            if detection.search(headers.get(HTTP_HEADER.X_CACHE, "")) is not None:
                return True
            if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
                return True