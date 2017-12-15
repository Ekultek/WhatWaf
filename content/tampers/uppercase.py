__example_payload__ = '<script>alert("test");</script>'
__type__ = "changing the payload into uppercase"


def tamper(payload, **kwargs):
    payload = str(payload)
    return payload.upper()