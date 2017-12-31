import random


__example_payload__ = "AND 1=1,<script>alert(\"test\");</script>"
__type__ = "implanting random Unicode characters into the payload"


def tamper(payload, **kwargs):
    identifiers = range(10)
    retval = ""
    for char in payload:
        modifier = random.choice(identifiers)
        if modifier == 3:
            retval += "%u00" + "%04x".upper() % random.randrange(0x10000)
            retval += char
        else:
            retval += char
    if retval == payload:
        return tamper(payload, **kwargs)
    return retval
