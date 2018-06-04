import re

from lib.settings import HTTP_HEADER


__product__ = "Airlock (Phion/Ergon)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"(ses|lb).(sess|al)?.([a-z])?(=)?\w+", re.I),
    )

    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None:
            return True
