import re


__product__ = "ConfigServer SPI WAF (ConfigServer Services)"


def detect(content, **kwargs):
    detection_schema = (
        re.compile(
            r"<img.src(=)?(.csf|.)?([-_]|data)"
            r"?(small)?.(image.)?(jpg|png)?(.)"
            r"*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-"
            r"9+/]{3}=)", re.I),
        re.compile(r"<img.src(=)?.csf[-_]?small.(jpg|png)?", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True