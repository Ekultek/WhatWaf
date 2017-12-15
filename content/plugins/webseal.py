import re


__product__ = "IBM Security Access Manager (WebSEAL)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"\bWebSEAL\b", re.I), re.compile(r"\bIBM\b", re.I)
    )
    for detection in list(detection_schema):
        if detection.search(content) is not None:
            return True