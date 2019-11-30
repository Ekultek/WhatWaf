import re


__product__ = "Google Web Services"


def detect(content, **kwargs):
    status = kwargs.get("status", 0)
    content = str(content)
    detection_schema = (
        re.compile("your.client.has.issued.a.malformed.or.illegal.request", re.I),
        re.compile("our.systems.have.detected.unusual.traffic")
    )
    if status == 400 or status == 429:
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
