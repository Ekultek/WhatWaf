import random

__example_payload__ = "SELECT user FROM information_schema.tables AND user = 'test user';"
__type__ = "replacing the spaces in the payload with either the tab character or eight spaces"


def tamper(payload, **kwargs):
    retval = ""
    for char in payload:
        edit = random.choice(range(0, 10))
        if edit >= 5 and char.isspace():
            retval += "        "
        elif edit <= 6 and char.isspace():
            retval += r"\t"
        else:
            retval += char
    return str(retval)
