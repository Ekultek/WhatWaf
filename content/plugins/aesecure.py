import re


__product__ = "aeSecure (WAF)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})

    detection_schema = (
        re.compile(r"aesecure.denied.png", re.I),
    )
    header_check = (
        headers.get("aeSecure-code", ""),
        headers.get("AeSecure-Code", ""),
        headers.get("aesecure-code", "")
    )
    for head in header_check:
        if head != "":
            return True
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
