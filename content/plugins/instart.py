import re


__product__ = "Instart Logic (Palo Alto)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})

    detection_schema = (
        re.compile(r"instartrequestid", re.I),
    )

    if headers.get("X-Instart-Request-ID", "") != "":
        return True
    if headers.get("X-Instart-CacheKeyMod", "") != "":
        return True
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
