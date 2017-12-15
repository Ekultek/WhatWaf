import re


__product__ = "Application Security Manager (F5 Networks)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"the.requested.url.was.rejected..please.consult.with.your.administrator.", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
