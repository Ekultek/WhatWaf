import re


__product__ = "360 Web Application Firewall (360)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    status = kwargs.get("status", None)
    detection_schema = (
        re.compile(r".wzws.waf.cgi.", re.I),
        re.compile(r"wangzhan\.360\.cn", re.I)
    )
    for detection in detection_schema:
        if status == 493:
            if detection.search(content) is not None:
                return True
        if detection.search(content) is not None:
            return True
        if detection.search(headers.get("X-Powered-By-360wzb", "")) is not None:
            return True
