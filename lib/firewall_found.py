import re
import sys
import json
import hashlib
import base64
import urllib2

import requests
from bs4 import BeautifulSoup

import lib.settings
import lib.formatter

try:
    raw_input
except Exception:
    input = raw_input


def create_identifier(data):
    obj = hashlib.sha1()
    obj.update(data)
    return obj.hexdigest()[1:10]


def get_token(path):
    """
    we know what this is for
    """
    with open(path) as _token:
        data = _token.read()
        token, n = data.split(":")
        for _ in range(int(n)):
            token = base64.b64decode(token)
    return token


def ensure_no_issue(param, url="https://github.com/Ekultek/WhatWaf/issues"):
    """
    ensure that there is not already an issue that has been created for yours
    """
    req = requests.get(url)
    param = re.compile(param)
    if param.search(req.content) is not None:
        return True
    return False


def find_url(params, search="https://github.com/ekultek/whatwaf/issues"):
    """
    get the URL that your issue is created at
    """
    retval = "https://github.com{}"
    href = None
    searcher = re.compile(params, re.I)
    req = requests.get(search)
    status, html = req.status_code, req.content
    if status == 200:
        split_information = str(html).split("\n")
        for i, line in enumerate(split_information):
            if searcher.search(line) is not None:
                href = split_information[i - 1]
    if href is not None:
        soup = BeautifulSoup(href, "html.parser")
        for item in soup.findAll("a"):
            link = item.get("href")
            return retval.format(link)
    return None


def request_firewall_issue_creation(path):
    """
    request the creation and create the issue
    """
    question = raw_input(
        "do you want to create an issue with the unknown firewall to possibly get it implemented[y/N]: "
    )
    if question.lower().startswith("y"):
        with open(path) as firewall_data:
            identifier = create_identifier(firewall_data.readline())
            full_fingerprint = firewall_data.read()
            issue_title = "Unknown Firewall ({})".format(identifier)

            def __hide_url(args=sys.argv):
                url_index = args.index("-u") + 1
                hidden_url = ''.join([x.replace(x, "*") for x in str(args[url_index])])
                args.pop(url_index)
                args.insert(url_index, hidden_url)
                return ' '.join(args)

        issue_data = {
            "title": issue_title,
            "body": "WhatWaf version: `{}`\n"
                    "Running context: `{}`\n"
                    "Fingerprint:\n```\n<!---\n{}\n```".format(
                lib.settings.VERSION, __hide_url(), full_fingerprint
            )
        }

        _json_data = json.dumps(issue_data)
        if sys.version_info > (3,):  # python 3
            _json_data = _json_data.encode("utf-8")

        if not ensure_no_issue(identifier):
            req = urllib2.Request(
                url="https://api.github.com/repos/ekultek/whatwaf/issues", data=_json_data,
                headers={"Authorization": "token {}".format(get_token(lib.settings.TOKEN_PATH))}
            )
            urllib2.urlopen(req, timeout=10).read()
            lib.formatter.info(
                "this firewalls fingerprint has successfully been submitted with the title '{}', "
                "URL '{}'".format(
                    issue_title, find_url(identifier)
                )
            )
        else:
            lib.formatter.error(
                "someone has already sent in this firewalls fingerprint here: {}".format(find_url(identifier))
            )

