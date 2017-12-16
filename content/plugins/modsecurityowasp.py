import re


__product__ = "Mod Security (OWASP CSR)"


def detect(content, **kwargs):
    content = str(content)
    status = kwargs.get("status", None)
    detection_schema = (
        re.compile(r"not.acceptable", re.I),
        re.compile(r"additionally\S.a.406.not.acceptable", re.I)
    )
    for detection in detection_schema:
        if status == 406:
            if detection.search(content) is not None:
                return True
