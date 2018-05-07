import os
import re
import sys
import random
import string
import platform

import requests
from bs4 import BeautifulSoup

import lib.formatter

# version number <major>.<minor>.<commit>
VERSION = "0.3.2"

# version string
VERSION_TYPE = "(#dev)" if VERSION.count(".") > 1 else "(#stable)"

# cool looking banner
BANNER = """\b\033[1m
                          ,------.  
                         '  .--.  ' 
,--.   .--.   ,--.   .--.|  |  |  | 
|  |   |  |   |  |   |  |'--'  |  | 
|  |   |  |   |  |   |  |    __.  | 
|  |.'.|  |   |  |.'.|  |   |   .'  
|         |   |         |   |___|   
|   ,'.   |hat|   ,'.   |af .---.   
'--'   '--'   '--'   '--'   '---'  
><script>alert("WhatWaf?<|>v{}{}");</script>
\033[0m""".format(VERSION, VERSION_TYPE)

# plugins (waf scripts) path
PLUGINS_DIRECTORY = "{}/content/plugins".format(os.getcwd())

# tampers (tamper scripts) path
TAMPERS_DIRECTORY = "{}/content/tampers".format(os.getcwd())

# directory to do the importing for the WAF scripts
PLUGINS_IMPORT_TEMPLATE = "content.plugins.{}"

# directory to do the importing for the tamper scripts
TAMPERS_IMPORT_TEMPLATE = "content.tampers.{}"

# link to the create a new issue page
ISSUES_LINK = "https://github.com/Ekultek/WhatWaf/issues/new"

# regex to detect the URL protocol (http or https)
PROTOCOL_DETECTION = re.compile("http(s)?")

# name provided to unknow nfirewalls
UNKNOWN_FIREWALL_NAME = "Unknown Firewall"

# fingerpritn path for unknown firewalls
UNKNOWN_PROTECTION_FINGERPRINT_PATH = "{}/.whatwaf".format(os.path.expanduser("~"))

# request token path
TOKEN_PATH = "{}/content/files/auth.key".format(os.getcwd())

# default user-agent
DEFAULT_USER_AGENT = "whatwaf/{} (Language={}; Platform={})".format(
    VERSION, sys.version.split(" ")[0], platform.platform().split("-")[0]
)

# payloads for detecting the WAF, at least one of
# these payloads `should` trigger the WAF and provide
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
        "xp_cmdshell('cat ../../../etc/passwd')#"  # thank you sqlmap
    ),
    '<img src="javascript:alert(\'XSS\');">',
    "'))) AND 1=1,SELECT * FROM information_schema.tables ((('",
    "' )) AND 1=1 (( ' -- rgzd",
    ";SELECT * FROM information_schema.tables WHERE 2>1 AND 1=1 OR 2=2 -- qdEf '",
    "' OR '1'=1 '", "OR 1=1"
)

# random home pages to try and get cookies
RAND_HOMEPAGES = (
    "index.php", "index.exe", "index.html", "index.py", "index.pl", "index.exe",
    "phpadmin.php", "home.php", "home.html", "home.py", "home.pl", "home.exe",
    "phpcmd.exe","index.phpcmd.exe", "index.html", "index.htm", "index.shtml",
    "index.php", "index.php5", "index.php5.exe", "index.php4.exe", "index.php4",
    "index.php3", "index.cgi", "default.html", "default.htm", "home.html", "home.htm",
    "Index.html", "Index.htm", "Index.shtml", "Index.php", "Index.cgi", "Default.html",
    "Default.htm", "Home.html", "Home.htm", "placeholder.html"
)


class HTTP_HEADER:
    """
    HTTP request headers list, putting it in a class because
    it's just easier to grab them then to retype them over
    and over again
    """
    ACCEPT              = "Accept"
    ACCEPT_CHARSET      = "Accept-Charset"
    ACCEPT_ENCODING     = "Accept-Encoding"
    ACCEPT_LANGUAGE     = "Accept-Language"
    AUTHORIZATION       = "Authorization"
    CACHE_CONTROL       = "Cache-Control"
    CONNECTION          = "Connection"
    CONTENT_ENCODING    = "Content-Encoding"
    CONTENT_LENGTH      = "Content-Length"
    CONTENT_RANGE       = "Content-Range"
    CONTENT_TYPE        = "Content-Type"
    COOKIE              = "Cookie"
    EXPIRES             = "Expires"
    HOST                = "Host"
    IF_MODIFIED_SINCE   = "If-Modified-Since"
    LAST_MODIFIED       = "Last-Modified"
    LOCATION            = "Location"
    PRAGMA              = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION    = "Proxy-Connection"
    RANGE               = "Range"
    REFERER             = "Referer"
    REFRESH             = "Refresh"
    SERVER              = "Server"
    SET_COOKIE          = "Set-Cookie"
    TRANSFER_ENCODING   = "Transfer-Encoding"
    URI                 = "URI"
    USER_AGENT          = "User-Agent"
    VIA                 = "Via"
    X_CACHE             = "X-Cache"
    X_POWERED_BY        = "X-Powered-By"
    X_DATA_ORIGIN       = "X-Data-Origin"
    X_FRAME_OPT         = "X-Frame-Options"
    X_FORWARDED_FOR     = "X-Forwarded-For"
    X_SERVER            = "X-Server"


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
    error_retval = (0, "", {})

    try:
        req = requests.get(url, params=headers, proxies=proxies, timeout=15)
        soup = BeautifulSoup(req.content, "html.parser")
        return req.status_code, soup, req.headers
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        return error_retval


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

    supported_proxies = ("socks5", "socks4", "http", "https")

    invalid_msg = "invalid switches detected, switch {} cannot be used in conjunction with switch {}"
    proxy_msg = "running behind proxy '{}'"

    if proxy is not None and tor:
        lib.formatter.error(invalid_msg.format("--tor", "--proxy"))
        exit(1)
    if agent is not None and use_random_agent:
        lib.formatter.error(invalid_msg.format("--ra", "--pa"))
        exit(1)
    if tor:
        proxy = "socks5://127.0.0.1:9050"
    if agent is None:
        agent = DEFAULT_USER_AGENT
    if use_random_agent:
        agent = get_random_agent()
    if proxy is not None:
        if any(item in proxy for item in supported_proxies):
            lib.formatter.info(proxy_msg.format(proxy))
        else:
            lib.formatter.error(
                "you did not provide a supported proxy protocol, "
                "supported protocols are '{}'. check your proxy and try again".format(
                    ", ".join([p for p in supported_proxies])
                )
            )
            exit(1)
    else:
        lib.formatter.warn("it is highly advised to use a proxy when using WhatWaf", minor=True)
    if agent is not None:
        lib.formatter.info("using User-Agent '{}'".format(agent))
    return proxy, agent


def produce_results(found_tampers):
    """
    produce the results of the tamper scripts, if any this
    """
    spacer = "-" * 30
    if len(found_tampers) > 0:
        lib.formatter.success("apparent working tampers for target:")
        print(spacer)
        for i, tamper in enumerate(found_tampers, start=1):
            description, example, load = tamper
            load = str(load).split(" ")[1].split("'")[1]
            print("(#{}) description: tamper payload by {}\nexample: '{}'\nload path: {}".format(
                i, description, example, load
            ))
            if i != len(found_tampers):
                print("\n")
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


def auto_assign(url, ssl=False):
    """
    check if a protocol is given in the URL if it isn't we'll auto assign it
    """
    if PROTOCOL_DETECTION.search(url) is None:
        if ssl:
            lib.formatter.warn("no protocol discovered, assigning HTTPS (SSL)")
            return "https://{}".format(url.strip())
        else:
            lib.formatter.warn("no protocol found assigning HTTP")
            return "http://{}".format(url.strip())
    else:
        if ssl:
            lib.formatter.info("forcing HTTPS (SSL) connection")
            items = PROTOCOL_DETECTION.split(url)
            item = items[-1].split("://")
            item[0] = "https://"
            return ''.join(item)
        else:
            return url.strip()


def create_fingerprint(url, content, status, headers):
    """
    create the unknown firewall fingerprint file
    """
    if not os.path.exists(UNKNOWN_PROTECTION_FINGERPRINT_PATH):
        os.mkdir(UNKNOWN_PROTECTION_FINGERPRINT_PATH)

    __replace_http = lambda x: x.split("/")
    fingerprint = "<!---\nHTTP 1.1\nStatus code: {}\nHTTP headers: {}\n--->\n{}".format(
        status, headers, content
    )

    filename = __replace_http(url)[2]
    if "www" not in filename:
        filename = "www.{}".format(filename)
    full_file_path = "{}/{}".format(UNKNOWN_PROTECTION_FINGERPRINT_PATH, filename)
    if not os.path.exists(full_file_path):
        with open(full_file_path, "a+") as log:
            log.write(fingerprint)
    else:
        lib.formatter.warn("fingerprint has already been created")
    return full_file_path



