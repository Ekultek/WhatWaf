import re


__product__ = "Barikode Web Application Firewall"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile("<\w+>barikode<.\w+>", re.I),
        re.compile("<h\d{1}>forbidden.access<.h\d{1}>", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True