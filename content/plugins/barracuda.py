import re

from lib.settings import HTTP_HEADER


__product__ = "Barracuda Web Application Firewall (Barracuda Networks, Inc.)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    content = str(content)

    detection_schema = (
        re.compile(r"\Abarra.counter.session(=)?", re.I),
        re.compile(r"(\A|\b)?barracuda.", re.I),
        re.compile(r"barracuda.networks(.)?.inc", re.I)
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None:
            return True
        if detection.search(content) is not None:
            return True
