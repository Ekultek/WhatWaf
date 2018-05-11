import re


__product__ = "ASP.NET Generic Web Application Protection (ASP.NET MS)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"x.aspnet.version", re.I), re.compile(r"potentially.dangerous.request.querystring", re.I),
    )
    for detection in detection_schema:
        if headers is not None:
            for header in headers.keys():
                if detection.search(header) is not None:
                    return True
        if detection.search(content) is not None:
            return True