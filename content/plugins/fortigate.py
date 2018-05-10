import re

from lib.settings import HTTP_HEADER


__product__ = "FortiWeb Web Application Firewall (Fortinet)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    content = str(content)
    detection_schema = (
        re.compile(r"<.+>powered.by.fortinet<.+.>", re.I),
        re.compile(r"<.+>fortigate.ips.sensor<.+.>", re.I),
        re.compile(r"fortigate", re.I), re.compile(r".fgd_icon", re.I),
        re.compile(r"\AFORTIWAFSID=", re.I), re.compile(r"application.blocked.", re.I),
        re.compile(r".fortiGate.application.control", re.I),
        re.compile(r"(http(s)?)?://\w+.fortinet(.\w+:)?", re.I),
        re.compile(r"fortigate.hostname", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        if detection.search(headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None:
            return True