import re


__product__ = "DynamicWeb Injection Check (DynamicWeb)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    status = kwargs.get("status", 0)
    detection_schema = (
        re.compile(r"dw.inj.check", re.I),
    )
    if status == 403:
        for detection in detection_schema:
            if detection.search(headers.get("X-403-status-by", "")) is not None:
                return True