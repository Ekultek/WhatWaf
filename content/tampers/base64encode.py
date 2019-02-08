import base64


__example_payload__ = "<script>alert("");</script>"
__type__ = "encoding the payload into its base64 equivalent"


def tamper(payload, **kwargs):
    try:
        payload = str(payload)
        return str(base64.b64encode(payload))
    except TypeError:
        payload = payload.encode("utf-8")
        return base64.b64encode(payload).decode("ascii")
