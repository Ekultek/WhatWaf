import re

from lib.settings import HTTP_HEADER


__product__ = "ASP.NET Generic Website Protection (MS)"


def detect(content, **kwargs):
    detected = 0
    content = str(content)
    headers = kwargs.get("headers", {})

    detection_schema = (
        re.compile("this.generic.403.error.means.that.the.authenticated", re.I),
        re.compile("request.could.not.be.understood", re.I),
        re.compile("potentially.dangerous.request", re.I),
        re.compile("runtime.error", re.I),
        re.compile("asp.net(.+)?", re.I),
        re.compile("a.potentially.dangerous.request.path.value.was.detected.from.the.client", re.I),
        re.compile("asp.net.sessionid", re.I)
    )
    x_powered_by = headers.get(HTTP_HEADER.X_POWERED_BY, "")
    asp_header = headers.get("X-ASPNET-Version", "")
    set_cookie = headers.get(HTTP_HEADER.SET_COOKIE, "")
    asp_header_2 = headers.get("asp-id", "")
    for detection in detection_schema:
        if detection.search(content) is not None:
            detected += 1
        if detection.search(set_cookie) is not None:
            detected += 1
    detected += 1 if asp_header != "" else 0
    if detection_schema[4].search(x_powered_by) is not None:
        detected += 1
    if asp_header_2 != "":
        detected += 1
    if detected >= 2:
        return True
