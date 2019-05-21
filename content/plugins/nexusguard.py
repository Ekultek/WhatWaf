# issue #260, thanks for the new waf!

import re


__product__ = "NexusGuard Security (WAF)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile("nexus(.)?guard", re.I),
        re.compile("((http(s)?://)?speresources.)?nexusguard.com.wafpage", re.I),
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
