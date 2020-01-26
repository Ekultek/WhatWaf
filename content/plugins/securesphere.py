import re


__product__ = "Imperva SecureSphere (Imperva)"


def detect(content, **kwargs):
    content = str(content)
    detected = 0
    detection_schema = (
        re.compile(r"<h2>error<.h2>"),
        re.compile(r"<title>error<.title>", re.I),
        re.compile(r"<b>error<.b>", re.I),
        re.compile(r'<td.class="(errormessage|error)".height="[0-9]{1,3}".width="[0-9]{1,3}">', re.I),
        re.compile(r"the.incident.id.(is|number.is).", re.I),
        re.compile(r"page.cannot.be.displayed", re.I),
        re.compile(r"contact.support.for.additional.information", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            detected += 1
    if detected >= 2:
        return True
    if re.search("the.destination.of.your.request.has.not.been.configured", content, re.I) is not None:
        return True
