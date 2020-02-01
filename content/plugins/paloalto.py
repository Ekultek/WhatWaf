import re


__product__ = "Palo Alto Firewall (Palo Alto Networks)"


def detect(content, **kwargs):
    content = str(content)
    detection_schemas = (
        re.compile(r"has.been.blocked.in.accordance.with.company.policy"),
        re.compile(r".>Virus.Spyware.Download.Blocked<.")
    )
    for detection in detection_schemas:
        if detection.search(content) is not None:
            return True