import re


__product__ = "XSS/CSRF Filtering Protection (CodeIgniter)"


def detect(content, **kwargs):
    status = kwargs.get("status", None)
    detection_schema = (
        re.compile(r"the.uri.you.submitted.has.disallowed.characters", re.I),
    )
    for detection in detection_schema:
        if status is not None and status == 400:
            if detection.search(content) is not None:
                return True
