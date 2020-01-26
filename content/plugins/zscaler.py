import re

from lib.settings import HTTP_HEADER


__product__ = "Zscaler Cloud Firewall (WAF)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    detection_schema = (
        re.compile(r"zscaler(.\d+(.\d+)?)?", re.I),
        re.compile(r"zscaler", re.I)
    )
    for detection in detection_schema:
        if headers is not None:
            if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
                return True
        if detection.search(content) is not None:
            return True