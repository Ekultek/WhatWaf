import re

__product__ = "Shadow Daemon Opensource (WAF)"


def detect(content, **kwargs):
    content = str(content)
    status = kwargs.get("status", None)
    detection_schema = (
        re.compile(r"<h\d{1}>\d{3}.forbidden<.h\d{1}>", re.I),
        re.compile(r"request.forbidden.by.administrative.rules.", re.I)
    )
    if status is not None and status == 403:
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
