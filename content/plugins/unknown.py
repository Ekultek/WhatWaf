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
        re.compile(r"blocked", re.I), re.compile(r"illegal", re.I),
        re.compile(r"reported", re.I), re.compile(r"ip.logged", re.I),
        re.compile(r"ip.address.logged", re.I), re.compile(r"not.acceptable"),
        re.compile(r"not.authorized", re.I), re.compile(r"unauthorized", re.I),
        re.compile(r"access.forbidden", re.I), re.compile(r"waf", re.I),
        re.compile(r"ids", re.I), re.compile(r"unacceptable.request", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        for head in headers.keys():
            if detection.search(headers[head]) is not None:
                return True
            if detection.search(head) is not None:
                return True


