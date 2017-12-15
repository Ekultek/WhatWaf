import string


__example_payload__ = 'AND 1=1,<script>alert("1,2,3,4,5);</script>'
__type__ = "enclosing numbers into brackets"


def tamper(payload, **kwargs):
    payload = str(payload)
    to_enclose = string.digits
    retval = ""
    for char in payload:
        if char in to_enclose:
            retval += "[{}]".format(char)
        else:
            retval += char
    return retval
