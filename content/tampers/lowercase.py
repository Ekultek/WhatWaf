__example_payload__ = "AND 1=1"
__type__ = "turning the payload into its lowercase equivalent"


def tamper(payload, **kwargs):
    payload = str(payload)
    return payload.lower()
