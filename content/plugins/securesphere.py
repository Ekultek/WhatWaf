import re


__product__ = "Imperva SecureSphere (Imperva)"


def detect(content, **kwargs):
    content = str(content)
    detected = 0
    detection_schema = (
        re.compile("<h2>error<.h2>"),
        re.compile("<title>error<.title>", re.I),
        re.compile("<b>error<.b>", re.I),
        re.compile('<td.class="(errormessage|error)".height="[0-9]{1,3}".width="[0-9]{1,3}">', re.I),
        re.compile("the.incident.id.(is|number.is).", re.I),
        re.compile("page.cannot.be.displayed", re.I),
        re.compile("contact.support.for.additional.information", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            detected += 1
    if detected >= 2:
        return True
    if re.search("the.destination.of.your.request.has.not.been.configured", content, re.I) is not None:
        return True
