import re


__example_payload__ = "' AND 1=1 OR 2=2 '"
__description__ = "mask the booleans with their symbolic counterparts"


def tamper(payload, **kwargs):
    return re.sub(r"(?i)and", "%26%26", re.sub(r"(?i)or", "%7C%7C", payload))
