import re


__product__ = "Sabre Firewall (WAF)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"dxsupport@sabre.com", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
