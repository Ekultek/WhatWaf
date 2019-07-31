import re


__product__ = "UEWaf (UCloud)"


def detect(content, **kwargs):
    detection_schema = (
        re.compile(r"http(s)?.//ucloud", re.I),
        re.compile(r"uewaf(.deny.pages)", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True