__example_payload__ = "&;lt'"
__type__ = "changing the payload into it's ordinal equivalent"


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
