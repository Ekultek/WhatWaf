import re

from lib.settings import HTTP_HEADER


__product__ = "Yundun Web Application Firewall (Yundun)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    status = kwargs.get("status", None)
    detection_schema = (
        re.compile(r"YUNDUN", re.I),
        re.compile(r"^yd.cookie=(\w+)?", re.I),
        re.compile(r"http(s)?.//(www)?.(\w+)?(.)?yundun(.com)?", re.I)
    )
    if headers is not None:
        for detection in detection_schema:
            if status is not None:
                if status == 461:
                    if detection.search(content) is not None:
                        return True
            if detection.search(headers.get(HTTP_HEADER.X_CACHE, "")) is not None:
                return True
            if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
                return True
            if detection.search(headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None:
                return True