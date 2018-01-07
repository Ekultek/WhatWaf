import string
try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus


__example_payload__ = "<img src=x onerror=\"input\">"
__type__ = "double URL encoding the payload characters"


def tamper(payload, **kwargs):
    danger_chars = string.punctuation + " "
    extra_danger_chars = ("_", ".")
    retval = ""
    for char in list(payload):
        if char not in danger_chars or char == "*":
            retval += char
        elif char == extra_danger_chars[0]:
            retval += quote_plus("%5F")
        elif char == extra_danger_chars[1]:
            retval += quote_plus("%2E")
        else:
            retval += quote_plus(quote_plus(char))
    return retval
