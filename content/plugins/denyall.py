import re

from lib.settings import HTTP_HEADER


__product__ = "Deny All Web Application Firewall (DenyAll)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"\Acondition.intercepted", re.I),
        re.compile(r"\Asessioncookie=", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None:
            return True
