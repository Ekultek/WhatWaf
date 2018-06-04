import re

from lib.settings import HTTP_HEADER


__product__ = "Varnish FireWall (OWASP)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"\bxid. \d+", re.I),
        re.compile(r"varnish\Z", re.I),
        re.compile(r"varnish"), re.I,
        re.compile(r"\d+")
    )
    try:
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
            if detection.search(headers.get(HTTP_HEADER.VIA, "")) is not None:
                return True
            if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
                return True
            if detection.search(headers.get("X-Varnish", "")) is not None:
                return True
    except:
        pass
