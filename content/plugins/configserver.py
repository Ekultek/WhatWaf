import re


__product__ = "CSF (ConfigServer Security & Firewall)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r".>the.firewall.on.this.server.is.blocking.your.connection.<+", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
