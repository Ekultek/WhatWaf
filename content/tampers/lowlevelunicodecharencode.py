__example_payload__ = "SELECT FIELD FROM information_schema.tables"
__type__ = "changing specific payload characters into their Unicode equivalent"


def tamper(payload, **kwargs):
    unicode_changes = {
        '1': 'B9', '2': 'B2', '3': 'B3', 'D': 'D0',
        'T': 'DE', 'Y': 'DD', 'a': 'AA', 'e': 'F0',
        'o': 'BA', 't': 'FE', 'y': 'FD', '|': 'A6',
        'd': 'D0', 'A': 'AA', 'E': 'F0', 'O': 'BA'
    }
    retval = ""
    # if there's not characters in it, we'll just skip this one
    if not any(c in payload for c in unicode_changes.keys()):
        return payload
    for char in payload:
        if char in unicode_changes.keys():
            retval += u"\\u00{}".format(unicode_changes[char])
        else:
            retval += char
    return retval