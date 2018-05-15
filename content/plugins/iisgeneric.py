import re


__product__ = "IIS Generic Website Protection (Internet Information Services)"


def detect(content, **kwargs):
    detection_schema = (
        re.compile(r"iis.(\d.\d)?.detailed.error", re.I),
        re.compile(r"this.is.a.generic.403.error.and.means.the.authenticated", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True