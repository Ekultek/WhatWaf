import os
import re
import sys
import json
import time
import random
import string
import base64
import platform
try:
    import urlparse
except Exception:
    # python 2.x doesn't have a ModuleNotFoundError so we'll just catch the exception I guess
    import urllib.parse as urlparse

import requests
from bs4 import BeautifulSoup

import lib.formatter

# version number <major>.<minor>.<commit>
VERSION = "0.9"

# version string
VERSION_TYPE = "($dev)" if VERSION.count(".") > 1 else "($stable)"

# cool looking banner
BANNER = """\b\033[1m
\t                          ,------.  
\t                         '  .--.  ' 
\t,--.   .--.   ,--.   .--.|  |  |  | 
\t|  |   |  |   |  |   |  |'--'  |  | 
\t|  |   |  |   |  |   |  |    __.  | 
\t|  |.'.|  |   |  |.'.|  |   |   .'  
\t|         |   |         |   |___|   
\t|   ,'.   |hat|   ,'.   |af .---.   
\t'--'   '--'   '--'   '--'   '---'  
"/><script>alert("\033[94mWhatWaf?\033[0m\033[1m<|>v{}{}\033[1m");</script>
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

# check if a query is in a URL or not
URL_QUERY_REGEX = re.compile(r"(.*)[?|#](.*){1}\=(.*)")

# name provided to unknown firewalls
UNKNOWN_FIREWALL_NAME = "Unknown Firewall"

# path to our home directory
HOME = "{}/.whatwaf".format(os.path.expanduser("~"))

# fingerprint path for unknown firewalls
UNKNOWN_PROTECTION_FINGERPRINT_PATH = "{}/fingerprints".format(HOME)

# JSON data file path
JSON_FILE_PATH = "{}/json_output".format(HOME)

# YAML data file path
YAML_FILE_PATH = "{}/yaml_output".format(HOME)

# CSV data file path
CSV_FILE_PATH = "{}/csv_output".format(HOME)

# request token path
TOKEN_PATH = "{}/content/files/auth.key".format(os.getcwd())

# default payloads path
DEFAULT_PAYLOAD_PATH = "{}/content/files/default_payloads.lst".format(os.getcwd())

# default user-agent
DEFAULT_USER_AGENT = "whatwaf/{} (Language={}; Platform={})".format(
    VERSION, sys.version.split(" ")[0], platform.platform().split("-")[0]
)

# payloads for detecting the WAF, at least one of
# these payloads `should` trigger the WAF and provide
# us with the information we need to identify what
# the WAF is, along with the information we will need
# to identify what tampering method we should use
# they are located in ./content/files/default_payloads.lst
WAF_REQUEST_DETECTION_PAYLOADS = [p.strip() for p in open(DEFAULT_PAYLOAD_PATH).readlines()]

# random home pages to try and get cookies
RAND_HOMEPAGES = (
    "index.php", "index.exe", "index.html", "index.py", "index.pl", "index.exe",
    "phpadmin.php", "home.php", "home.html", "home.py", "home.pl", "home.exe",
    "phpcmd.exe", "index.phpcmd.exe", "index.html", "index.htm", "index.shtml",
    "index.php", "index.php5", "index.php5.exe", "index.php4.exe", "index.php4",
    "index.php3", "index.cgi", "default.html", "default.htm", "home.html", "home.htm",
    "Index.html", "Index.htm", "Index.shtml", "Index.php", "Index.cgi", "Default.html",
    "Default.htm", "Home.html", "Home.htm", "placeholder.html"
)

# this is a regex to validate a URL. It was taken from Django's URL validation technique
# reference can be found here:
# `https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not/7160778#7160778`
URL_VALIDATION = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE
)


class InvalidURLProvided(Exception): pass


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
    X_BACKSIDE_TRANS = "X-Backside-Transport"


def validate_url(url):
    """
    validate a provided URL
    """
    return URL_VALIDATION.match(url)


def get_query(url):
    """
    get the query parameter out of a URL
    """
    data = urlparse.urlparse(url)
    query = "{}?{}".format(data.path, data.query)
    return query


def get_page(url, **kwargs):
    """
    get the website page, this will return a `tuple`
    containing the status code, HTML and headers of the
    requests page
    """
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", DEFAULT_USER_AGENT)
    provided_headers = kwargs.get("provided_headers", None)
    throttle = kwargs.get("throttle", 0)
    req_timeout = kwargs.get("timeout", 15)
    request_method = kwargs.get("request_method", "GET")
    post_data = kwargs.get("post_data", " ")

    if post_data.isspace():
        items = list(post_data)
        for i, item in enumerate(items):
            if item == "=":
                items[i] = "{}{}{}".format(items[i - 1], items[i], random_string(length=7))
        post_data = ''.join(items)

    if request_method == "GET":
        req = requests.get
    elif request_method == "POST":
        req = requests.post
    else:
        req = requests.get

    if provided_headers is None:
        headers = {"Connection": "close", "User-Agent": agent}
    else:
        headers = {}
        if type(provided_headers) == dict:
            for key, value in provided_headers.items():
                headers[key] = value
            headers["User-Agent"] = agent
        else:
            headers = provided_headers
            headers["User-Agent"] = agent
    proxies = {} if proxy is None else {"http": proxy, "https": proxy}
    error_retval = ("", 0, "", {})

    time.sleep(throttle)

    try:
        req = req(url, headers=headers, proxies=proxies, timeout=req_timeout, data=post_data)
        soup = BeautifulSoup(req.content, "html.parser")
        return "{} {}".format(request_method, get_query(url)), req.status_code, soup, req.headers
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
        lib.formatter.warn(
            "it is highly advised to use a proxy when using WhatWaf. do so by passing the proxy flag "
            "(IE `--proxy http://127.0.0.1:9050`) or by passing the Tor flag (IE `--tor`)", minor=True
        )
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
            try:
                load = str(load).split(" ")[1].split("'")[1]
            except IndexError:
                pass
            print("(#{}) description: tamper payload by {}\nexample: '{}'\nload path: {}".format(
                i, description, example, load
            ))
            if i != len(found_tampers):
                print("\n")
        print(spacer)
    else:
        lib.formatter.warn("no valid bypasses discovered with provided payloads")


def random_string(acceptable=string.ascii_letters, length=5, use_json=False, use_yaml=False, use_csv=False):
    """
    create a random string for some of the tamper scripts that
    need a random string in order to work properly
    """
    random_chars = [random.choice(acceptable) for _ in range(length)]
    if use_json:
        return "{}.json".format(''.join(random_chars))
    elif use_yaml:
        return "{}.yaml".format(''.join(random_chars))
    elif use_csv:
        return "{}.csv".format(''.join(random_chars))
    else:
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


def create_fingerprint(url, content, status, headers, req_data=None, speak=False):
    """
    create the unknown firewall fingerprint file
    """
    if not os.path.exists(UNKNOWN_PROTECTION_FINGERPRINT_PATH):
        os.makedirs(UNKNOWN_PROTECTION_FINGERPRINT_PATH)

    __replace_http = lambda x: x.split("/")
    __replace_specifics = lambda u: "http://{}".format(u.split("/")[2])

    try:
        url = __replace_specifics(url)
    except Exception:
        lib.formatter.warn("full URL will be displayed to the public if an issue is created")
        url = url

    fingerprint = "<!---\n{}\nStatus code: {}\n{}\n--->\n{}".format(
        "GET {} HTTP/1.1".format(url) if req_data is None else "{} HTTP/1.1".format(req_data),
        str(status),
        '\n'.join("{}: {}".format(h, k) for h, k in headers.items()),
        str(content)
    )

    filename = __replace_http(url)[2]
    if "www" not in filename:
        filename = "www.{}".format(filename)
    full_file_path = "{}/{}".format(UNKNOWN_PROTECTION_FINGERPRINT_PATH, filename)
    if not os.path.exists(full_file_path):
        with open(full_file_path, "a+") as log:
            log.write(fingerprint)
        if speak:
            lib.formatter.success("fingerprint saved to '{}'".format(full_file_path))
    return full_file_path


def write_to_file(filename, path, data, **kwargs):
    """
    write the data to a file
    """
    write_yaml = kwargs.get("write_yaml", False)
    write_json = kwargs.get("write_json", False)
    write_csv = kwargs.get("write_csv", False)

    full_path = "{}/{}".format(path, filename)

    if not os.path.exists(path):
        os.makedirs(path)
    if write_json and not write_yaml and not write_csv:
        with open(full_path, "a+") as _json:
            _json_data = json.loads(data)
            json.dump(_json_data, _json, sort_keys=True, indent=4)
    elif write_yaml and not write_json and not write_csv:
        try:
            # there is an extra dependency that needs to be installed for you to save to YAML
            # we'll check if you have it or not
            import yaml

            with open(full_path, "a+") as _yaml:
                _yaml_data = yaml.load(data)
                yaml.dump(_yaml_data, _yaml, default_flow_style=False)
        except ImportError:
            # if you don't we'll just skip the saving and warn you
            lib.formatter.warn(
                "you do not have the needed dependency to save YAML files, to install the dependency run "
                "`pip install pyyaml`, skipping file writing"
            )
            return None
    elif write_csv and not write_json and not write_yaml:
        import csv

        _json_data = json.loads(data)
        try:
            csv_data = [
                ["url", "is_protected", "protection", "working_tampers"],
                [
                    _json_data["url"], _json_data["is protected"],
                    _json_data[
                        "identified firewall"
                    ] if _json_data["identified firewall"] is not None else "None",
                    _json_data[
                        "apparent working tampers"
                    ] if _json_data["apparent working tampers"] is not None else "None"
                ]
            ]
        except KeyError:
            pass
        with open(full_path, "a+") as _csv:
            writer = csv.writer(_csv)
            writer.writerows(csv_data)
    return full_path


def is_64(_string):
    """
    will allow you to tell if a string is base64 or not
    """
    if len(_string) != 4 and len(_string) % 4 == 0:
        try:
            data = base64.b64decode(string)
            if all(c in string.printable for c in _string):
                return data
            else:
                return _string
        except Exception:
            # assume the string is not base64 and return the string
            return _string
    else:
        return _string


def parse_burp_request(filename):
    """
    parse an XML file from Burp Suite and make a request based on what is parsed
    """
    import xml.etree.ElementTree as Parser

    retval = {}
    tmp = {}

    tree = Parser.parse(filename)
    root = tree.getroot()
    burp_attributes = root.attrib

    lib.formatter.info("parsing XML file from Burp version: {}; creation time: {}".format(
        burp_attributes["burpVersion"], burp_attributes["exportTime"]
    ))

    try:
        retval["base_url"] = is_64(root[0][1].text.strip())
        retval["protocol"] = is_64(root[0][4].text.strip())
        retval["request_method"] = is_64(root[0][5].text.split(" ")[-1])
        retval["request_headers"] = is_64(root[0][8].text.strip())

        for header in retval["request_headers"].split("\n"):
            if retval["request_method"] not in header and retval["base_url"] not in header and "Host" not in header:
                data = header.split(":")
                try:
                    tmp[data[0]] = data[1].strip()
                except IndexError:
                    retval["post_data"] = ''.join(data)
        retval["request_headers"] = {}
        if "post_data" not in retval:
            retval["post_data"] = None
        retval["request_headers"] = tmp

        return retval
    except IndexError:
        lib.formatter.fatal("it appears the burp request file provided has no usable information in it")
        exit(-1)


def check_version():
    """
    check the version number for updates
    """
    version_url = "https://raw.githubusercontent.com/Ekultek/WhatWaf/master/lib/settings.py"
    req = requests.get(version_url)
    content = req.text
    current_version = content.split("\n")[21].split("=")[-1].split('"')[1]
    my_version = VERSION
    if not current_version == my_version:
        lib.formatter.warn("new version: {} is available".format(current_version))
