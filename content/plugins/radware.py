import re


__product__ = "Radware (AppWall WAF)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r".\bcloudwebsec.radware.com\b.", re.I),
        re.compile(r"<.+>unauthorized.activity.has.been.detected<.+.>", re.I),
        re.compile(r"with.the.following.case.number.in.its.subject:.\d+.", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
