import re


__product__ = "Shield Security"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile("blocked.by.the.shield", re.I),
        re.compile("transgression(\(s\))?.against.this", re.I),
        re.compile("url(.)?.form.or.cookie.data.wasn.t.appropriate", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
