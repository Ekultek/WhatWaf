import re

from lib.settings import HTTP_HEADER


__product__ = "DOSarrest (DOSarrest Internet Security)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"dosarrest", re.I),
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
        if headers.get("X-DIS-Request-ID") is not None:
            return True
