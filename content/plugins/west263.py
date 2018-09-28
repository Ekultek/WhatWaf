import re

from lib.settings import HTTP_HEADER


__product__ = "West236 Firewall"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"(.)?wt(\d+)?cdn(.)?", re.I),
    )
    for detection in detection_schema:
        if headers is not None:
            if detection.search(headers.get(HTTP_HEADER.X_CACHE, "")) is not None:
                return True
