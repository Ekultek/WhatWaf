import re


__product__ = "Website Security SiteGuard (Lite)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r">Powered.by.SiteGuard.Lite<", re.I),
        re.compile(r"refuse.to.browse", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True