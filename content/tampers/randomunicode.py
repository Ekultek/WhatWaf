import random
import string


__example_payload__ = "AND 1=1,<script>alert(\"test\");</script>"
__type__ = "inserting random UTF-8 characters into the payload"


def tamper(payload, **kwargs):

    def glyph(n=6):
        res = u""
        for i in range(n):
            res = u"\\u%04x" % random.randrange(0xD7FF)
        return res

    identifiers = range(10)
    retval = ""
    for char in payload:
        modifier = random.choice(identifiers)
        if modifier == 3:
            retval += glyph()
            retval += char
        else:
            retval += char
    if retval == payload:
        return tamper(payload, **kwargs)
    return retval
