import re

from lib.settings import HTTP_HEADER

__product__ = "360 Web Application Firewall (360)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r".wzws.waf.cgi.", re.I),
        re.compile(r"wangzhan\.360\.cn", re.I),
        re.compile(r"qianxin.waf", re.I),
        re.compile(r"360wzws"),
        re.compile(r"transfer.is.blocked", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if detection.search(headers.get("X-Powered-By-360wzb", "")) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
