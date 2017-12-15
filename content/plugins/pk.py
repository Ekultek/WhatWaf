import re


__product__ = "pkSecurityModule (IDS)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"<.+>pkSecurityModule\W..\WSecurity.Alert<.+.>", re.I),
        re.compile(r"<.+http(s)?.//([w]{3})?.kitnetwork.\w+.+>", re.I),
        re.compile(r"<.+>A.safety.critical.request.was.discovered.and.blocked.<.+.>", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True