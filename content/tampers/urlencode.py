import string


__example_payload__ = "<script>alert('test');</script>"
__type__ = "encoding punctuation characters by their URL encoding equivalent"


def tamper(payload, **kwargs):
    to_encode = string.punctuation
    retval = ""
    if not any(s in payload for s in to_encode):
        return payload
    for char in payload:
        if char in to_encode:
            retval += "%{}".format(ord(char))
        else:
            retval += char
    return retval