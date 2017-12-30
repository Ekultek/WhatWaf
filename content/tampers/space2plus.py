__example_payload__ = "' AND 1=1 '"
__type__ = "changing the spaces in the payload into a plus sign"


def tamper(payload, **kwargs):
    modifier = "+"
    retval = ""
    for char in payload:
        if char == " ":
            retval += modifier
        else:
            retval += char
    return retval
