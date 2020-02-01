import re


__product__ = "Teros Web Application Firewall (Citrix)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    detection_schema = (
        re.compile(r"st8(id|.wa|.wf)?.?(\d+|\w+)?", re.I),
    )
    if headers is not None:
        for detection in detection_schema:
            if len(headers) != 0:
                for header in headers.keys():
                    if detection.search(headers[header]) is not None:
                        return True
