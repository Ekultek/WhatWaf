import re


__product__ = "Janusec Application Gateway (WAF)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile("janusec", re.I),
        re.compile("http(s)?\W+(www.)?janusec.(com|net|org)", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
