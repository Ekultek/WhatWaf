__example_payload__ = "' AND 1=1 '"
__type__ = "pre-pending a NULL character at the start of the payload"


def tamper(payload, **kwargs):
    return "%00{}".format(payload)