import re


__product__ = "aeSecure (WAF)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)

    detection_schema = (
        re.compile("aesecure.denied.png", re.I),
    )
    header_check = (
        headers.get("aeSecure-code", None),
        headers.get("AeSecure-Code", None),
        headers.get("aesecure-code", None)
    )
    for head in header_check:
        if head is not None:
            return True
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
