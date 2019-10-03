import re

from lib.settings import HTTP_HEADER


__product__ = "DiDiYun WAF (DiDi)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile("(http(s)?://)(sec-waf.|www.)?didi(static|yun)?.com(/static/cloudwafstatic)?", re.I),
        re.compile("didiyun", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
    if headers is not None:
        server = headers.get(HTTP_HEADER.SERVER, "")
        if server == "DiDi-SLB":
            return True
