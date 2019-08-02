import re

from lib.settings import HTTP_HEADER


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
        re.compile(r"unauthorized", re.I), re.compile(r"permission", re.I),
        re.compile(r"waf", re.I), re.compile(r"ids", re.I), re.compile(r"ips", re.I),
        re.compile(r"automated", re.I), re.compile(r"suspicious", re.I),
        re.compile(r"denied", re.I), re.compile("attack(ed)?", re.I),
        re.compile(r"rejected", re.I), re.compile(r"security", re.I),
        re.compile("detected", re.I), re.compile(r"protected(.\w+)?", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        for head in headers.keys():
            if detection.search(headers[head]) is not None:
                return True
            if detection.search(head) is not None:
                if not any(head == c for c in [HTTP_HEADER.CONTENT_SECURITY, HTTP_HEADER.STRICT_TRANSPORT]):
                    return True
        unknown_verification_regex = re.compile(r"(\b)?<.+>*({})(\S+|\d+|\w+)?(<.+.>)?".format(detection.pattern), re.I)
        if unknown_verification_regex.search(content) is not None:
            return True
