import re

from lib.settings import HTTP_HEADER


__product__ = "Varnish/CacheWall WAF"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"\bxid. \d+", re.I),
        re.compile(r"varnish", re.I),
        re.compile(r".>.?security.by.cachewall.?<.", re.I),
        re.compile(r"cachewall", re.I),
        re.compile(r".>access.is.blocked.according.to.our.site.security.policy.<+", re.I)
    )
    try:
        possible_headers = ("X-Varnish", "X-Cachewall-Action", "X-Cachewall-Reason")
        if headers.get(HTTP_HEADER.SERVER, "") == "Varnish":
            return True
        if any([h in k for k in headers.keys() for h in possible_headers]):
            return True

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
