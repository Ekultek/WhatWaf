import re


__product__ = "Litespeed webserver Generic Protection"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"litespeed.web.server", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
