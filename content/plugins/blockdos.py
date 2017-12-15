import re


from lib.settings import HTTP_HEADER


__product__ = "BlockDos DDoS protection (BlockDos)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"blockdos\.net", re.I),
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
