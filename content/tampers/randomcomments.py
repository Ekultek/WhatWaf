import random
import string


__example_payload__ = "' AND 1=1 ' OR 10=11,<script>alert('');</script>"
__type__ = "implanting random comments into the payload"


def tamper(payload, **kwargs):
    modifer = "/**/"
    characters = string.ascii_letters
    retval = ""
    for char in payload:
        random_chars = [random.choice(characters) for _ in range(10)]
        if char in random_chars:
            retval += "{}{}".format(modifer, char)
        else:
            retval += char
    if modifer not in retval:
        retval = tamper(payload, **kwargs)
    return retval
