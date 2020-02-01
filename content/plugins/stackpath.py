import re


__product__ = "Stackpath WAF (StackPath)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"action.that.triggered.the.service.and.blocked", re.I),
        re.compile(r"<h2>sorry,.you.have.been.blocked.?<.h2>", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
