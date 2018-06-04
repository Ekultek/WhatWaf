import re


from lib.settings import HTTP_HEADER


__product__ = "Yunjiasu Web Application Firewall (Baidu)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"fh(l)?", re.I),
        re.compile(r"yunjiasu.nginx", re.I)
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.X_SERVER, "")) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
