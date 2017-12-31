import re


__product__ = "Unknown Firewall"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    status = kwargs.get("status", None)
    # make sure that it's not just a `didn't find what you're looking for` page
    # this will probably help out a lot with random WAF detection
    if status == 200 or "not found" in content.lower():
        return False
    detection_schema = (
        re.compile("blocked", re.I), re.compile("illegal", re.I),
        re.compile("reported", re.I), re.compile("ip.logged", re.I),
        re.compile("ip.address.logged", re.I), re.compile(r"not.acceptable"),
        re.compile("not.authorized", re.I), re.compile(r"unauthorized", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if detection.search(str(headers)) is not None:
            return True


