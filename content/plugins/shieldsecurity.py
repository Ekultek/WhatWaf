import re


__product__ = "Shield Security"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"blocked.by.the.shield", re.I),
        re.compile(r"transgression(\(s\))?.against.this", re.I),
        re.compile(r"url.{1,2}form.or.cookie.data.wasn.t.appropriate", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
