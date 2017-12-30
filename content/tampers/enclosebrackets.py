import string


__example_payload__ = 'AND 1=1,<script>alert("1,2,3,4,5);</script>'
__type__ = "enclosing numbers into brackets"


def tamper(payload, **kwargs):
    payload = str(payload)
    to_enclose = string.digits
    if not any(i in list(payload) for i in to_enclose):
        return payload
    retval = ""
    for char in payload:
        if char in to_enclose:
            retval += "[{}]".format(char)
        else:
            retval += char
    return retval
