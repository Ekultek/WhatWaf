import re

from lib.settings import HTTP_HEADER


__product__ = "AkamaiGHost Website Protection (Akamai Global Host)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    content = str(content)
    detection_schema = (
        re.compile(r"you.don.t.have.permission.to.access", re.I),
        re.compile(r"<.+>access.denied<.+.>", re.I), re.compile(r"akamaighost", re.I),
        re.compile(r"ak.bmsc.")
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None:
            return True
        if detection.search(content) is not None:
            return True
    header_searcher = re.compile("akamaighost", re.I)
    if header_searcher.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
        return True
