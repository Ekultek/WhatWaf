__example_payload__ = r"""&\lt' AND 1=1 ',<script>alert("test");</script>"""
__type__ = "changing the payload characters into their HTML entities"


def tamper(payload, **kwargs):
    payload = str(payload)
    retval = ""
    skip = ";"
    encoding_schema = {
        " ": "&nbsp;", "<": "&lt;", ">": "&gt;",
        "&": "&amp;", '"': "&quot;", "'": "&apos;",
    }
    if not any(c in payload for c in encoding_schema.keys()):
        return payload
    for char in payload:
        if char in encoding_schema.keys():
            retval += encoding_schema[char]
        elif char not in encoding_schema.keys() and char != skip:
            retval += char
        else:
            retval += char
    return retval
