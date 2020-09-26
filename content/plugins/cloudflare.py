import re

from lib.settings import HTTP_HEADER


__product__ = "CloudFlare Web Application Firewall (CloudFlare)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    detection_schemas = (
        re.compile(r"cloudflare.ray.id.|var.cloudflare.", re.I),
        re.compile(r"cloudflare.nginx", re.I),
        re.compile(r"..cfduid=([a-z0-9]{43})?", re.I),
        re.compile(r"cf[-|_]ray(..)?([0-9a-f]{16})?[-|_]?(dfw|iad)?", re.I),
        re.compile(r".>attention.required!.\|.cloudflare<.+", re.I),
        re.compile(r"http(s)?.//report.(uri.)?cloudflare.com(/cdn.cgi(.beacon/expect.ct)?)?", re.I),
        re.compile(r"ray.id", re.I)
    )
    server = headers.get(HTTP_HEADER.SERVER, "")
    cookie = headers.get(HTTP_HEADER.COOKIE, "")
    set_cookie = headers.get(HTTP_HEADER.SET_COOKIE, "")
    cf_ray = headers.get(HTTP_HEADER.CF_RAY, "")
    if cf_ray != "":
        return True
    expect_ct = headers.get(HTTP_HEADER.EXPECT_CT, "")
    if "__cfduid" in set_cookie or "cloudflare" in expect_ct:
        return True
    for detection in detection_schemas:
        if detection.search(content) is not None:
            return True
        if detection.search(server) is not None:
            return True
        if detection.search(cookie) is not None:
            return True
        if detection.search(set_cookie) is not None:
            return True
        if detection.search(expect_ct) is not None:
            return True

