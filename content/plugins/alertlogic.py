import re


__product__ = "Alert Logic (SIEMless Threat Management)"


def detect(content, **kwargs):
    detection_count = 0
    detection_schema = (
        re.compile(r".>requested.url.cannot.be.found<.", re.I),
        re.compile(r"proceed.to.homepage", re.I),
        re.compile(r"back.to.previous.page", re.I),
        re.compile(r"we('re|.are)?sorry.{1,2}but.the.page.you.are.looking.for.cannot", re.I),
        re.compile(r"reference.id.?", re.I),
        re.compile(r"page.has.either.been.removed.{1,2}renamed", re.I)
    )
    detected_successfully_count = len(detection_schema)
    for detection in detection_schema:
        if detection.search(content) is not None:
            detection_count += 1
    if detection_count == detected_successfully_count:
        return True
