import re


__product__ = "Open Source Web Application Firewall (Modsecurity)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"ModSecurity|NYOB", re.I),
        re.compile(r"mod.security", re.I),
        re.compile(r"This.error.was.generated.by.mod.security", re.I),
        re.compile(r"web.server at", re.I),
        re.compile(r"page.you.are.(accessing|trying)?.(to|is)?.(access)?.(is|to)?.(restricted)?", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True