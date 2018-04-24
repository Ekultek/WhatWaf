__example_payload__ = "SELECT user FROM information_schema.tables"
__type__ = "changing the spaces to the tab character '\\t'"


def tamper(payload, **kwargs):
    return str(payload).replace(" ", r"\t")