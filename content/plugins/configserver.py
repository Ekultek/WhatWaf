import re


__product__ = "ConfigServer SPI WAF (ConfigServer Services)"


def detect(content, **kwargs):
    detection_schema = (
        re.compile(r"<img.src(=)?.csf[-_]?small.(jpg|png)?", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True