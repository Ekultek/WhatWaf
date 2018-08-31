import re

from lib.settings import HTTP_HEADER


__product__ = "Varnish/CacheWall WAF"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"\bxid. \d+", re.I),
        re.compile(r"varnish\Z", re.I),
        re.compile(r"varnish"), re.I,
        re.compile(r"\d+"),
        re.compile(r"<.+>(.)?security.by.cachewall(.)?<.+.>", re.I),
        re.compile(r"cachewall", re.I)
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
        possible_headers = ("X-Varnish", "X-Cachewall-Action", "X-Cachewall-Reason")
        if any([h in k for k in headers.keys() for h in possible_headers]):
            return True
    except:
        pass
