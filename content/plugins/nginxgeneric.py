import re


__product__ = "Nginx Generic Protection"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile("nginx", re.I),
        re.compile("you.do(not|n.t)?.have.permission.to.access.this.document")
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
