import re

from lib.settings import HTTP_HEADER

__product__ = "Sucuri Firewall (Sucuri Cloudproxy)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"Access Denied - Sucuri Website Firewall"),
        re.compile(r"Sucuri WebSite Firewall - CloudProxy - Access Denied"),
        re.compile(r"Questions\?.+cloudproxy@sucuri\.net")
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if re.compile(r"X-Sucuri-ID", re.I).search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True