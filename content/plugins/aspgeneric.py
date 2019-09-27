import re

from lib.settings import HTTP_HEADER


__product__ = "ASP.NET Generic Website Protection (MS)"


def detect(content, **kwargs):
    detected = 0
    content = str(content)
    headers = kwargs.get("headers", None)

    detection_schema = (
        re.compile("this.generic.403.error.means.that.the.authenticated", re.I),
        re.compile("request.could.not.be.understood", re.I),
        re.compile("potentially.dangerous.request", re.I),
        re.compile("runtime.error", re.I),
        re.compile("asp.net(.+)?", re.I)
    )
    x_powered_by = headers.get(HTTP_HEADER.X_POWERED_BY, None)
    asp_header = headers.get("X-ASPNET-Version", None)
    for detection in detection_schema:
        if detection.search(content) is not None:
            detected += 1
    if asp_header is not None:
        detected += 1
    if x_powered_by is not None:
        if detection_schema[4].search(x_powered_by) is not None:
            detected += 1
    if detected >= 2:
        return True
