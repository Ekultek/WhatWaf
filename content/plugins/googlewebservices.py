import re


__product__ = "Google Web Services (G-Cloud)"


def detect(content, **kwargs):
    status = kwargs.get("status", 0)
    content = str(content)
    detection_schema = (
        re.compile(r"your.client.has.issued.a.malformed.or.illegal.request", re.I),
        re.compile(r"our.systems.have.detected.unusual.traffic", re.I),
        re.compile(r"block(ed)?.by.g.cloud.security.policy.+", re.I)
    )
    if status == 400 or status == 429 or status == 500:
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
