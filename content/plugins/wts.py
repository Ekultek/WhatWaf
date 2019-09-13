import re


__product__ = "WTS-WAF (Web Application Firewall)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"wts.waf(\w+)?", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True