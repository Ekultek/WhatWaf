import re

from lib.settings import HTTP_HEADER


__product__ = "WatchGuard WAF"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"(request.denied.by.)?watchguard.firewall", re.I),
        re.compile(r"watchguard(.technologies(.inc)?)?", re.I),
    )
    server = headers.get(HTTP_HEADER.SERVER, "")
    if "watchguard" in server.lower():
        return True
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
