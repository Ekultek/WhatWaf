__example_payload__ = "' AND 1=1 '"
__type__ = "changing the spaces in the payload into a NULL character"


def tamper(payload, **kwargs):
    modifier = "%00"
    return str(payload).replace(" ", modifier)
