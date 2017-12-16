import re

from lib.settings import HTTP_HEADER


__product__ = "Incapsula Web Application Firewall (Incapsula/Imperva)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"incap_ses|visid_incap", re.I),
        re.compile(r"incapsula", re.I),
        re.compile(r"incapsula.incident.id", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None:
            return True
        if detection.search(headers.get("X-CDN", "")) is not None:
            return True