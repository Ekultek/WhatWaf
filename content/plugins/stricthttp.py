import re


# https://docs.spring.io/spring-security/site/docs/4.2.12.RELEASE/apidocs/org/springframework/security/web/firewall/StrictHttpFirewall.html
__product__ = "StrictHttpFirewall (WAF)"


def detect(content, **kwargs):
    content = str(content)
    status = kwargs.get("status", 0)
    detection_schema = (
        re.compile(r"the.request.was.rejected.because.the.url.contained.a.potentially.malicious.string", re.I),
    )
    if status == 500:
        for detection in detection_schema:
            if detection.search(content) is not None:
                return True
