import re

from lib.settings import HTTP_HEADER


__product__ = "SonicWALL Firewall (Dell)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"This.request.is.blocked.by.the.SonicWALL", re.I),
        re.compile(r"Dell.SonicWALL", re.I),
        re.compile(r"\bDell\b", re.I),
        re.compile(r"Web.Site.Blocked.+\bnsa.banner", re.I),
        re.compile(r"SonicWALL", re.I),
        re.compile(r"<.+>policy.this.site.is.blocked<.+.>", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True