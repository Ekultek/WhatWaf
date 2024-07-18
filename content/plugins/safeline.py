import re

__product__ = "Chaitin SafeLine (WAF)"
# https://github.com/chaitin/SafeLine

def detect(content, **kwargs):
  content = str(content)
  detection_schema = (
    re.compile(r"event_id:\s*\w{32}", re.I),
    re.compile(r"SafeLine", re.I)
)
  for detection in detection_schema:
    if detection.search(content) is not None:
        return True
