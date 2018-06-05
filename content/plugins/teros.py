import re


__product__ = "Teros Web Application Firewall (Citrix)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"st8(id|.wa|.wf)?(.)?(\d+|\w+)?", re.I),
    )
    if headers is not None:
        for detection in detection_schema:
            for header in headers.keys():
                if detection.search(headers[header]) is not None:
                    return True
