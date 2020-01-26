import re


__product__ = "AliYunDun (WAF)"


def detect(content, **kwargs):
    status = kwargs.get("status", 0)
    if status is not None and status == 405:
        detection_schema = (
            re.compile(r"error(s)?.aliyun(dun)?.(com|net)", re.I),
            re.compile(r"http(s)?://(www.)?aliyun.(com|net)", re.I)
        )
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
