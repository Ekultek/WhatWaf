import re


__product__ = "Powerful Firewall (MyBB plugin)"


def detect(content, **kwargs):
    status = kwargs.get("status", None)
    detection_schema = (
        re.compile(r"Powerful Firewall", re.I),
        re.compile(r"http(s)?...tiny.cc.powerful.firewall", re.I)
    )
    if status is not None:
        if status == 403:
            for detection in detection_schema:
                if detection.search(content) is not None:
                    return True