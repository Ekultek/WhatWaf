__example_payload__ = "SELECT * FROM information_schema.tables"
__description__ = "replacing the payloads spaces with tab character (\\t)"


def tamper(payload, **kwargs):
    return payload.replace(" ", r"\t")