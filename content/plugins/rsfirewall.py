import re


__product__ = "RSFirewall (Joomla WAF)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"com.rsfirewall.403.forbidden", re.I),
        re.compile(r"com.rsfirewall.event", re.I),
        re.compile(r"(\b)?rsfirewall(\b)?", re.I),
        re.compile(r"rsfirewall", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
