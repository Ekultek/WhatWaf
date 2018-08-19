import re


__product__ = "AnYu Web Application Firewall (Anyu Technologies)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"sorry(.)?.your.access.has.been.intercept(ed)?.by.anyu", re.I),
        re.compile(r"anyu", re.I),
        re.compile(r"anyu(-)?.the.green.channel", re.I)
    )
    try:
        event_id = headers["WZWS-RAY"] if headers is not None else None
    except:
        event_id = None
    if event_id is not None:
        detection_schema = list(detection_schema)
        detection_schema.append(re.compile(r"{}".format(event_id), re.I))
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
