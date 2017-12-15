import base64


__example_payload__ = "<script>alert("");</script>"
__type__ = "encoding the payload into it's base64 equivalent"


def tamper(payload, **kwargs):
    payload = str(payload)
    return base64.b64encode(payload)