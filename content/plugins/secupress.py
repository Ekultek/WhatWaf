import re


__product__ = "SecuPress (Wordpress WAF)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"<h\d*>secupress<.", re.I),
        re.compile(r"block.id.{1,2}bad.url.contents.<.", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
