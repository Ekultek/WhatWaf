import re

from lib.settings import HTTP_HEADER


__product__ = "IBM Security Access Manager (WebSEAL)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"webseal.error.message.template", re.I),
        re.compile(r"webseal.server.received.an.invalid.http.request", re.I)
    )
    if headers.get(HTTP_HEADER.SERVER, "") == "WebSEAL":
        return True
    for detection in list(detection_schema):
        if detection.search(content) is not None:
            return True