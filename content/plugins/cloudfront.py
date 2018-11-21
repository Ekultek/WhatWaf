import re


__product__ = "CloudFront Firewall (Amazon)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"[a-zA-Z0-9]{,60}.cloudfront.net", re.I),
        re.compile(r"cloudfront", re.I),
        re.compile(r"x.amz.cf.id|nguardx", re.I)
    )
    for detection in detection_schema:
        if headers is not None:
            for header in headers.keys():
                if detection.search(headers[header]) is not None:
                    return True
