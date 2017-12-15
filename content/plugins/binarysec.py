import re


from lib.settings import HTTP_HEADER


__product__ = "BinarySEC Web Application Firewall (BinarySEC)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"x.binarysec.via", re.I),
        re.compile(r"x.binarysec.nocache", re.I),
        re.compile(r"binarysec", re.I),
        re.compile(r"\bbinarysec\b", re.I)
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
        if detection.search(str(headers)) is not None:
            return True
