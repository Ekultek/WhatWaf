import re

from lib.settings import HTTP_HEADER


__product__ = "Nginx Generic Protection"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"nginx", re.I),
    )
    for detection in detection_schema:
        if headers is not None:
            if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
                return True