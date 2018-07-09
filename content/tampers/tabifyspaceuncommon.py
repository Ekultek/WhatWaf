__example_payload__ = "UNION SELECT * FROM users WHERE user = 'admin';"
__description__ = "replacing the spaces in the payload with 8 spaces to simulate a tab character"


def tamper(payload, **kwargs):
    return payload.replace(" ", "        ")