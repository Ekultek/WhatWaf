import re

from lib.settings import HTTP_HEADER


__item__ = "Yunsuo Web Application Firewall (Yunsuo)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    content = str(content)
    detection_schema = (
        re.compile(r"<img.class=.yunsuologo.", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
    if re.search(r"yunsuo.session", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None:
        return True