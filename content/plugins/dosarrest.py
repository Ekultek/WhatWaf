import re

from lib.settings import HTTP_HEADER


__product__ = "DOSarrest (DOSarrest Internet Security)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"dosarrest", re.I),
        re.compile(r"x.dis.request.id", re.I)
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
        if headers is not None:
            for header in headers.keys():
                if detection.search(headers[header]) is not None:
                    return True
                if detection.search(header) is not None:
                    return True
