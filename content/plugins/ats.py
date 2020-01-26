import re

from lib.settings import HTTP_HEADER


__product__ = "Apache Traffic Server (ATS web proxy)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    if headers is not None:
        detection_schema = (
            re.compile(r"(\()?apachetrafficserver((\/)?\d+(.\d+(.\d+)?)?)", re.I),
            re.compile(r"ats((\/)?(\d+(.\d+(.\d+)?)?))?", re.I),
            re.compile(r"ats", re.I)
        )
        via = headers.get(HTTP_HEADER.VIA, "")
        server = headers.get(HTTP_HEADER.SERVER, "")
        for detection in detection_schema:
            if detection.search(via) is not None:
                return True
            if detection.search(server) is not None:
                return True
