import re

from lib.settings import HTTP_HEADER


__product__ = "Apache Generic"


def detect(content, **kwargs):
    content = str(content)
    status = kwargs.get("status", 0)
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"apache", re.I),
        re.compile(r".>you.don.t.have.permission.to.access+", re.I),
        re.compile(r"was.not.found.on.this.server", re.I),
        re.compile(r"<address>apache/([\d+{1,2}](.[\d+]{1,2}(.[\d+]{1,3})?)?)?", re.I),
        re.compile(r"<title>403 Forbidden</title>", re.I)
    )
    if status == 403:
        if detection_schema[0].search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
