import re

from lib.settings import HTTP_HEADER


__product__ = "Grey Wizard Protection"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"greywizard(.\d.\d(.\d)?)?", re.I), re.compile(r"grey.wizard.block", re.I),
        re.compile(r"(http(s)?.//)?(\w+.)?greywizard.com", re.I), re.compile(r"grey.wizard")
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
        gw_server = headers.get(HTTP_HEADER.GW_SERVER, None)
        server = headers.get(HTTP_HEADER.SERVER, None)
        if gw_server is not None:
            if detection.search(server) is not None:
                return True
        if server is not None:
            if detection.search(gw_server) is not None:
                return True