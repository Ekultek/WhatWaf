import re


__product__ = "Malcare (MalCare Security WAF)"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"malcare", re.I),
        re.compile(r".>login.protection<.+.><.+>powered.by<.+.>(<.+.>)?(.?malcare.-.pro|blogvault)?", re.I),
        re.compile(r".>firewall<.+.><.+>powered.by<.+.>(<.+.>)?(.?malcare.-.pro|blogvault)?", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
