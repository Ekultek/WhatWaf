import re


__product__ = "Google Web Services"


def detect(content, **kwargs):
    status = kwargs.get("status", 0)
    content = str(content)
    detection_schema = (
        re.compile("your.client.has.issued.a.malformed.or.illegal.request", re.I),
    )
    if status == 400:
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
