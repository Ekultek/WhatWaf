import re


__product__ = "Apache Generic"


def detect(content, **kwargs):
    content = str(content)
    status = kwargs.get("status", 0)
    detection_schema = (
        re.compile("apache", re.I),
        re.compile("You.don.t.have.permission.to.access", re.I),
        re.compile("was.not.found.on.this.server", re.I)
    )

    if status == 403:
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
