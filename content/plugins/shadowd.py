import re

__product__ = "Shadow Daemon Opensource (WAF)"


def detect(content, **kwargs):
    content = str(content)
    status = kwargs.get("status", 0)
    detection_schema = (
        re.compile(r"<h\d>\d{3}.forbidden<.h\d>", re.I),
        re.compile(r"request.forbidden.by.administrative.rules.", re.I)
    )
    if status is not None and status == 403:
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
