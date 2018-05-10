import re

from lib.settings import HTTP_HEADER


__product__ = "Apache generic website protection"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"apache", re.I),
        re.compile(r"<.+>apache/\d.\d.\d", re.I),
        re.compile(r"apache/\d.\d.\d.\([a-z]{3,15}\)", re.I),
        re.compile(r"apache.(\d+.\d+.\d+)?(.)?(\(\w+\))?", re.I)
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
        if detection.search(content) is not None:
            return True
