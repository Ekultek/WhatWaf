__example_payload__ = "<script>alert(\"XSS\");</script>"
__type__ = "changing certain characters in the payload into their ordinal equivalent"


def tamper(payload, **kwargs):
    payload = str(payload)
    retval = ""
    danger_characters = "%&<>/\\;'\""
    for char in payload:
        if char in danger_characters:
            retval += "%{}".format(ord(char) * 10 / 7)
        else:
            retval += char
    return retval
