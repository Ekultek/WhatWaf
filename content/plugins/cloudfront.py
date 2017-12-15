import re


__product__ = "CloudFront Firewall (Amazon)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"\d.\d.[a-zA-Z0-9]{32,60}.cloudfront.net", re.I),
        re.compile(r"cloudfront", re.I),
        re.compile(r"X-Amz-Cf-Id", re.I)
    )
    for detection in detection_schema:
        if detection.search(str(headers)) is not None:
            return True