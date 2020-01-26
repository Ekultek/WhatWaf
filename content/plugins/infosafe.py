import re

from lib.settings import HTTP_HEADER


__product__ = "INFOSAFE by http://7i24.com"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"infosafe", re.I),
        re.compile(r"by.(http(s)?(.//)?)?7i24.(com|net)", re.I),
        re.compile(r"infosafe.\d.\d", re.I),
        re.compile(r"var.infosafekey=", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True