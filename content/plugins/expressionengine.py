import re


__product__ = "ExpressionEngine (Ellislab WAF)"


def detect(content, **kwargs):
    detection_schema = (
        re.compile(r"<.+>error.-.expressionengine<.+.>", re.I),
        re.compile(r"<.+><.+>error<.+.>:.the.uri.you.submitted.has.disallowed.characters.<.+.>", re.I),
        re.compile(r"invalid.get.data", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
