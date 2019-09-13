import re

from lib.settings import HTTP_HEADER


__product__ = "CloudFlare Web Application Firewall (CloudFlare)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    content = str(content)
    detection_schemas = (
        re.compile(r"cloudflare.ray.id.|var.cloudflare.", re.I),
        re.compile(r"cloudflare.nginx", re.I),
        re.compile(r"..cfduid=([a-z0-9]{43})?", re.I),
        re.compile(r"cf[-|_]ray(..)?([0-9a-f]{16})?[-|_]?(dfw|iad)?", re.I),
        re.compile(r"<title>attention.required.(...)?cloudflare</title>", re.I),
        re.compile(r"http(s)?.//report.uri.cloudflare.com(/cdn.cgi(.beacon/expect.ct)?)?", re.I)
    )
    server = headers.get(HTTP_HEADER.SERVER, None)
    cookie = headers.get(HTTP_HEADER.COOKIE, None)
    set_cookie = headers.get(HTTP_HEADER.SET_COOKIE, None)
    cf_ray = headers.get(HTTP_HEADER.CF_RAY, None)
    expect_ct = headers.get(HTTP_HEADER.EXPECT_CT, None)
    for detection in detection_schemas:
        if detection.search(content) is not None:
            return True
        if server is not None:
            if detection.search(server) is not None:
                return True
        if cookie is not None:
            if detection.search(cookie) is not None:
                return True
        if set_cookie is not None:
            if detection.search(set_cookie) is not None:
                return True
        if cf_ray is not None:
            if detection.search(cf_ray) is not None:
                return True
        if expect_ct is not None:
            if detection.search(expect_ct) is not None:
                return True
    if "__cfuid" in set_cookie or "cloudflare" in expect_ct:
        return True
