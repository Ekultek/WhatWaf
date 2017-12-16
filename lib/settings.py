import os
import sys
import random
import string
import platform

import requests
from bs4 import BeautifulSoup

import lib.formatter

# version number
VERSION = "0.1.4"

# version string
VERSION_TYPE = "(#dev)" if VERSION.count(".") > 1 else "(stable)"

# github clone string
CLONE = "https://github.com/ekultek/whatwaf"

# cool looking banner
BANNER = """\033[1m
  (`\ .-') /` (`\ .-') /`,------.  
   `.( OO ),'  `.( OO ),'  .--.  ' 
,--./  .--. ,--./  .--. |  |  |  | 
|      |  | |      |  | '--'  |  | 
|  |   |  |,|  |   |  |,    __.  | 
|  |.'.|  |_|  |.'.|  |_)  |   .'  
|         | |         |    |___|   
|   ,'.   | |   ,'.   |    .---.   
'--'   '--' '--'   '--'    '---'  
><script>alert("WhatWaf?-v{}{}");</script>
\033[0m""".format(VERSION, VERSION_TYPE)

# plugins (waf scripts)
PLUGINS_DIRECTORY = "{}/content/plugins".format(os.getcwd())

# tampers (tamper scripts)
TAMPERS_DIRECTORY = "{}/content/tampers".format(os.getcwd())

# directory to do the importing for the WAF scripts
PLUGINS_IMPORT_TEMPALTE = "content.plugins.{}"

# directory to do the importing for the tamper scripts
TAMPERS_IMPORT_TEMPLATE = "content.tampers.{}"

# fingerpritn path for unknown firewalls
UNKNOWN_PROTECTION_FINGERPRINT_PATH = "{}/.whatwaf".format(os.path.expanduser("~"))

# default user-agent
DEFAULT_USER_AGENT = "whatwaf/{} (Language={}; Platform={})".format(
    VERSION, sys.version.split(" ")[0], platform.platform().split("-")[0]
)

# payload for detecting the WAF, at least one of
# these payloads should trigger the WAF and provide
# us with the information we need to identify what
# the WAF is, along with the information we will need
# to identify what tampering method we should use
WAF_REQUEST_DETECTION_PAYLOADS = (
    "<frameset><frame src=\"javascript:alert('XSS');\"></frameset>",
    " AND 1=1 ORDERBY(1,2,3,4,5) --;",
    '><script>alert("testing");</script>',
    (
        " AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',"
        "table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC "
        "xp_cmdshell('cat ../../../etc/passwd')#"
    ),
    '<img src="javascript:alert(\'XSS\');">',
    "'))) AND 1=1 OR 24=12 ((( '"

)


class HTTP_HEADER:
    """
    HTTP request headers list, putting it in a class because
    it's just easier to grab them then to retype them over
    and over again
    """
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    COOKIE = "Cookie"
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    REFRESH = "Refresh"
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_CACHE = "X-Cache"
    X_POWERED_BY = "X-Powered-By"
    X_DATA_ORIGIN = "X-Data-Origin"
    X_FRAME_OPT = "X-Frame-Options"
    X_FORWARDED_FOR = "X-Forwarded-For"
    X_SERVER = "X-Server"


def get_page(url, **kwargs):
    """
    get the website page, this will return a `tuple`
    containing the status code, HTML and headers of the
    requests page
    """
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", DEFAULT_USER_AGENT)
    headers = {"Connection": "close", "User-Agent": agent}
    proxies = {} if proxy is None else {"http": proxy, "https": proxy}
    req = requests.get(url, params=headers, proxies=proxies, timeout=15)
    soup = BeautifulSoup(req.content, "html.parser")
    return req.status_code, soup, req.headers


def get_random_agent(path="{}/content/files/user_agents.txt"):
    """
    grab a random user-agent from the file to pass as
    the HTTP User-Agent header
    """
    with open(path.format(os.getcwd())) as agents:
        items = [agent.strip() for agent in agents.readlines()]
        return random.choice(items)


def configure_request_headers(**kwargs):
    """
    configure the HTTP request headers with a user defined
    proxy, Tor, or a random User-Agent from the user-agent
    file
    """
    agent = kwargs.get("agent", None)
    proxy = kwargs.get("proxy", None)
    tor = kwargs.get("tor", False)
    use_random_agent = kwargs.get("random_agent", False)

    if proxy is not None and tor:
        lib.formatter.error("you cannot use Tor and a proxy at the same time")
        exit(1)
    if agent is not None and use_random_agent:
        lib.formatter.error("you cannot use a random agent and a personal agent at the same time")
        exit(1)
    if tor:
        proxy = "socks5://127.0.0.1:9050"
    if agent is None:
        agent = DEFAULT_USER_AGENT
    if use_random_agent:
        agent = get_random_agent()
    return proxy, agent


def produce_results(found_tampers):
    """
    produce the results of the tamper scripts, if any this
    """
    lib.formatter.success("apparent working tampers for target:")
    spacer = "-" * 30
    if len(found_tampers) > 0:
        print(spacer)
        for i, tamper in enumerate(found_tampers, start=1):
            description, example = tamper
            print("#{} tamper payload by {} (example: {})".format(i, description, example))
        print(spacer)
    else:
        lib.formatter.warn("no valid bypasses discovered with provided payloads")


def random_string(acceptable=string.ascii_letters, length=5):
    """
    create a random string for some of the tamper scripts that
    need a random string in order to work properly
    """
    random_chars = [random.choice(acceptable) for _ in range(length)]
    return ''.join(random_chars)
