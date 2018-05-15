import re


__product__ = "Anti Bot Protection (PerimeterX)"


def detect(content, **kwargs):
    detection_schema = (
        re.compile(r"access.to.this.page.has.been.denied.because.we.believe.you.are.using.automation.tool", re.I),
        re.compile(r"http(s)?://(www.)?perimeterx.\w+.whywasiblocked", re.I), re.compile(r"perimeterx", re.I),
        re.compile(r"(..)?client.perimeterx.*/[a-zA-Z]{8,15}/*.*.js", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True