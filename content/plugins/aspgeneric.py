import re

from lib.settings import HTTP_HEADER


__product__ = "ASP.NET Generic Website Protection (Microsoft)"


def detect(content, **kwargs):
    detected = 0
    content = str(content)
    headers = kwargs.get("headers", {})

    detection_schema = (
        re.compile(r"this.generic.403.error.means.that.the.authenticated", re.I),
        re.compile(r"request.could.not.be.understood", re.I),
        re.compile(r"<.+>a.potentially.dangerous.request(.querystring)?.+", re.I),
        re.compile(r"runtime.error", re.I),
        re.compile(r".>a.potentially.dangerous.request.path.value.was.detected.from.the.client+", re.I),
        re.compile(r"asp.net.sessionid", re.I),
        re.compile(r"errordocument.to.handle.the.request", re.I),
        re.compile(r"an.application.error.occurred.on.the.server", re.I),
        re.compile(r"error.log.record.number", re.I),
        re.compile(r"error.page.might.contain.sensitive.information", re.I),
        re.compile(r"<.+>server.error.in.'/'.application.+", re.I),
        re.compile("\basp.net\b", re.I)
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
    if detection_schema[4].search(x_powered_by) is not None or x_powered_by == "ASP.NET":
        detected += 1
    if asp_header_2 != "":
        detected += 1
    if detected >= 2:
        return True
