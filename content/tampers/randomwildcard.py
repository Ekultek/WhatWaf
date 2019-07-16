import random
import string


__example_payload__ = "/bin/cat /etc/passwd"
__type__ = "changing characters into a wildcard"


def tamper(payload, **kwargs):
    wildcard = ["*", "?"]
    safe_chars = string.punctuation + " "
    retval = ""
    for char in list(payload):
        if not any(p == char for p in safe_chars):
            do_it = random.randint(1, 10) <= 3
            if do_it:
                retval += random.choice(wildcard)
            else:
                retval += char
        else:
            retval += char
    return retval
