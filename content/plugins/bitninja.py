import re


__product__ = "Bitninja (WAF)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile("bitninja", re.I),
        re.compile("security.check.by.bitninja", re.I),
        re.compile("<.+>visitor.anti(\S)?robot.validation<.+.>", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
