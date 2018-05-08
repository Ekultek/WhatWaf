import re

from lib.settings import HTTP_HEADER

__product__ = "SafeDog WAF (SafeDog)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"(http(s)?)?(://)?(www|404|bbs|\w+)?.safedog.\w+", re.I),
        re.compile(r"waf(.?\d+(.)?\d+)", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.X_POWERED_BY, "")) is not None:
            return True
