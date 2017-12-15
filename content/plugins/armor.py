import re


__product__ = "Armor Protection (Armor Defense)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"\barmor\b", re.I),
        re.compile(r"blocked.by.website.protection.from.armour", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True