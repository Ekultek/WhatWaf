import re


__product__ = "SafeDog WAF (SafeDog)"


def detect(content, **kwargs):
    detection_schema = (
        re.compile(r"(http(s)?)?(://)?(www|404|bbs|\w+)?.safedog.\w+", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
