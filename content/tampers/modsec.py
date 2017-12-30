__example_payload__ = "AND 1=1"
__type__ = "putting the payload in-between a comment with obfuscation in it"


def tamper(payload, **kwargs):
    return "/*!00000{}*/".format(payload)
