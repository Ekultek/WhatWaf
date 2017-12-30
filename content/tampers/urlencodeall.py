__example_payload__ = "SELECT * FROM information_schema.tables"
__type__ = "encoding all characters in the payload into their URL encoding equivalent"


def tamper(payload, **kwargs):
    retval = ""
    for char in payload:
        retval += "%{}".format(ord(char))
    return retval
