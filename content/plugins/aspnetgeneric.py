import re


__product__ = "ASP.NET Generic Web Application Protection (ASP.NET MS)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"x.aspnet.version", re.I), re.compile(r"potentially.dangerous.request.querystring", re.I),
        re.compile(r"iis.(\d+.\d+)?.detailed.error", re.I), re.compile(r"asp.net", re.I),
        re.compile(r"this.is.a.generic.403.error.and.means.the.authenticated", re.I),
        re.compile(r"the.request.could.not.be.understood", re.I)
    )
    for detection in detection_schema:
        if headers is not None:
            for header in headers.keys():
                if detection.search(header) is not None:
                    return True
                if detection.search(headers[header]) is not None:
                    return True
        if detection.search(content) is not None:
            return True