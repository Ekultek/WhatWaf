import re


__product__ = "DoD Enterprise-Level Protection System (Department of Defense)"


def detect(content, **kwargs):
    detection_schema = (
        re.compile(r"dod.enterprise.level.protection.system", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True