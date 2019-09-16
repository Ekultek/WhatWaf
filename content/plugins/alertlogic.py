import re


__product__ = "Alert Logic (SIEMless Threat Management)"


def detect(content, **kwargs):
    detection_count = 0
    detection_schema = (
        re.compile("<.+>requested.url.cannot.be.found<.+.>", re.I),
        re.compile("proceed.to.homepage", re.I),
        re.compile("back.to.previous.page", re.I),
        re.compile("we('re|.are)?sorry(.)?.but.the.page.you.are.looking.for.cannot", re.I),
        re.compile("reference.id(.)?", re.I),
        re.compile("page.has.either.been.removed(.)?.renamed", re.I)
    )
    detected_successfully_count = len(detection_schema)
    for detection in detection_schema:
        if detection.search(content) is not None:
            detection_count += 1
    if detection_count == detected_successfully_count:
        return True
