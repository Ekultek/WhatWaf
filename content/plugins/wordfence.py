import re


__product__ = "Wordfence (Feedjit)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"generated.by.wordfence", re.I),
        re.compile(r"your.access.to.this.site.has.been.limited", re.I),
        re.compile(r"<.+>wordfence<.+.>", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
