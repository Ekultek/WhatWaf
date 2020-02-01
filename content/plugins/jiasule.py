import re

from lib.settings import HTTP_HEADER


__product__ = "Jiasule (WAF)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"^jsl(_)?tracking", re.I),
        re.compile(r"(__)?jsluid(=)?", re.I),
        re.compile(r"notice.jiasule", re.I),
        re.compile(r"(static|www|dynamic).jiasule.(com|net)", re.I)
    )
    for detection in detection_schema:
        if headers is not None:
            set_cookie = headers.get(HTTP_HEADER.SET_COOKIE, "")
            server = headers.get(HTTP_HEADER.SERVER, "")
            if any(detection.search(item) for item in [set_cookie, server]):
                return True
        if detection.search(content) is not None:
            return True
