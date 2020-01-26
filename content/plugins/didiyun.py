import re

from lib.settings import HTTP_HEADER


__product__ = "DiDiYun WAF (DiDi)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"(http(s)?://)(sec-waf.|www.)?didi(static|yun)?.com(/static/cloudwafstatic)?", re.I),
        re.compile(r"didiyun", re.I)
    )
    if headers is not None:
        server = headers.get(HTTP_HEADER.SERVER, "")
        if server == "DiDi-SLB":
            return True
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
