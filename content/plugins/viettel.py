import re


__product__ = "Viettel WAF (Cloudrity)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        # https://github.com/0xInfection/Awesome-WAF
        re.compile(r"<title>access.denied(...)?viettel.waf</title>", re.I),
        re.compile(r"viettel.waf.system", re.I),
        re.compile(r"(http(s).//)?cloudrity.com(.vn)?")
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
