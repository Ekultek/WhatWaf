import re

from lib.settings import HTTP_HEADER


__product__ = "Squid Proxy (IDS)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"squid", re.I),
        re.compile(r"Access control configuration prevents", re.I),
        re.compile(r"X.Squid.Error", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
        if detection.search(str(headers)) is not None:
            return True