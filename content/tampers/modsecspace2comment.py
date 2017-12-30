__example_payload__ = "SELECT * FROM information_schema.tables"
__type__ = "obfuscating payload by passing it between comments with obfuscation and changing spaces to comments"


def tamper(payload, **kwargs):
    modifier = "/**/"
    secondary_modifier = "/*!00000{}*/"
    retval = ""
    for char in payload:
        if char == " ":
            retval += modifier
        else:
            retval += char
    return secondary_modifier.format(retval)