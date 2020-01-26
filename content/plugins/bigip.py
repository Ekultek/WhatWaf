import re

from lib.settings import HTTP_HEADER


__product__ = "BIG-IP (F5 Networks)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"\ATS\w{4,}=", re.I),
        re.compile(r"bigipserver(.i)?|bigipserverinternal", re.I),
        re.compile(r"\AF5\Z", re.I),
        re.compile(r"^TS[a-zA-Z0-9]{3,8}=", re.I),
        re.compile(r"BigIP|BIG-IP|BIGIP"),
        re.compile(r"bigipserver", re.I),
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.COOKIE, "")) is not None:
            return True
