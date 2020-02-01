import re


__product__ = "dotDefender (Applicure Technologies)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"dotdefender.blocked.your.request", re.I),
    )

    if headers.get("X-dotDefender-denied", "") == "1":
        return True
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
