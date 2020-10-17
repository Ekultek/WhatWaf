import re


__product__ = "BitNinja (WAF)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"bitninja", re.I),
        re.compile(r"security.check.by.bitninja", re.I),
        re.compile(r".>visitor.anti(\S)?robot.validation<.", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
