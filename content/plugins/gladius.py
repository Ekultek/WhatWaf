__product__ = "Gladius network WAF (Gladius)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    if headers:
        if headers.get("gladius_blockchain_driven_cyber_protection_network_session", ""):
            return True
