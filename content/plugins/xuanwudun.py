import re


__product__ = "Xuanwudun WAF"


def detect(content, **kwargs):
    content = str(content)
    status = kwargs.get("status", 0)
    detection_schema = (
        re.compile(r"class=.(db)?waf.?(-row.)?>", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            if status is not None and status == 403:
                return True