import os
import re
import importlib

import lib.settings
import lib.formatter


class ScriptQueue(object):

    """
    This is where we will load all the scripts that we need to identify the firewall
    or to identify the possible bypass
    """

    def __init__(self, files_path, import_path, verbose=False):
        self.files = files_path
        self.path = import_path
        self.verbose = verbose
        self.skip_schema = ("__init__.py", ".pyc", "__")
        self.script_type = ''.join(self.path.split(".")[1].split())[:-1]

    def load_scripts(self):
        retval = []
        file_list = [f for f in os.listdir(self.files) if not any(s in f for s in self.skip_schema)]
        for script in sorted(file_list):
            script = script[:-3]
            if self.verbose:
                lib.formatter.debug("loading {} script '{}'".format(self.script_type, script))
            script = importlib.import_module(self.path.format(script))
            retval.append(script)
        return retval


class DetectionQueue(object):

    """
    Queue to add the HTML requests into, it will return a `tuple` containing status, html, and headers along with
    the amount of requests that have been made
    """

    def __init__(self, url, payloads, **kwargs):
        self.url = url
        self.payloads = payloads
        self.agent = kwargs.get("agent", lib.settings.DEFAULT_USER_AGENT)
        self.proxy = kwargs.get("proxy", None)
        self.verbose = kwargs.get("verbose", False)

    def get_response(self):
        response_retval = []
        for i, waf_vector in enumerate(self.payloads):
            url = self.url + "{}".format(waf_vector)
            if self.verbose:
                lib.formatter.payload(waf_vector.strip())
            try:
                response_retval.append((lib.settings.get_page(url, agent=self.agent, proxy=self.proxy)))
                if self.verbose:
                    lib.formatter.debug(
                        "response code: {}".format(response_retval[i][0])
                    )
            except Exception as e:
                if "ECONNRESET" in str(e):
                    lib.formatter.warn("possible network level firewall detected, received an aborted connection")
                    response_retval.append(None)
                else:
                    lib.formatter.error(
                        "failed to obtain target meta-data with payload {}, error: '{}'".format(
                            waf_vector.strip(), str(e)
                        )
                    )
                    response_retval.append(None)
        return response_retval


def encode(payload, script):
    script = importlib.import_module(script)
    return script.tamper(payload)


def find_failures(html, regs):
    for reg in regs:
        if reg.search(html) is not None or html == "" or html is None:
            return True
    return False


def get_working_tampers(url, norm_response, payloads, **kwargs):
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", None)
    verbose = kwargs.get("verbose", False)

    failed_schema = (
        re.compile("404", re.I), re.compile("captcha", re.I),
        re.compile("illegal", re.I), re.compile("forbidden", re.I),
        re.compile("blocked", re.I), re.compile("ip logged", re.I),
        re.compile("ip address logged", re.I), re.compile("not acceptable", re.I),
        re.compile("access denied", re.I)
    )
    lib.formatter.info("loading payload tampering scripts")
    tampers = ScriptQueue(
        lib.settings.TAMPERS_DIRECTORY, lib.settings.TAMPERS_IMPORT_TEMPLATE, verbose=verbose
    ).load_scripts()

    working_tampers = set()
    max_successful_payloads = 5
    normal_status, _, _ = norm_response
    lib.formatter.info("running tampering bypass checks")
    for tamper in tampers:
        load = tamper
        if verbose:
            lib.formatter.debug("currently tampering with script '{}".format(str(load).split(" ")[1].split(".")[-1]))
        for vector in payloads:
            vector = tamper.tamper(vector)
            if verbose:
                lib.formatter.payload(vector.strip())
            payloaded_url = "{}{}".format(url, vector)
            status, html, _ = lib.settings.get_page(payloaded_url, agent=agent, proxy=proxy, verbose=verbose)
            if not find_failures(str(html), failed_schema):
                if verbose:
                    if status != 0:
                        lib.formatter.debug("response code: {}".format(status))
                    else:
                        lib.formatter.debug("unknown response detected")
                if status != 404:
                    if status == 200:
                        working_tampers.add((tamper.__type__, tamper.tamper(tamper.__example_payload__), load))
            else:
                if verbose:
                    lib.formatter.warn("failure found in response content")
            if len(working_tampers) == max_successful_payloads:
                break
        if len(working_tampers) == max_successful_payloads:
            break
    return working_tampers


def detection_main(url, payloads, **kwargs):
    """
    main detection function
    """
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", lib.settings.DEFAULT_USER_AGENT)
    verbose = kwargs.get("verbose", False)

    lib.formatter.info("loading firewall detection scripts")
    loaded_plugins = ScriptQueue(
        lib.settings.PLUGINS_DIRECTORY, lib.settings.PLUGINS_IMPORT_TEMPALTE, verbose=verbose
    ).load_scripts()

    lib.formatter.set_color("gathering HTTP responses")
    responses = DetectionQueue(url, payloads, proxy=proxy, agent=agent, verbose=verbose).get_response()
    lib.formatter.set_color("gathering normal response to compare against")
    normal_response = lib.settings.get_page(url, proxy=proxy, agent=agent)

    unknown_firewall_name = "Unknown Firewall"
    amount_of_products = 0
    detected_protections = set()

    lib.formatter.info("running firewall detection checks")
    for item in responses:
        if item is not None:
            status, html, headers = item
            for detection in loaded_plugins:
                if detection.detect(str(html), status=status, headers=headers) is True:
                    if detection.__product__ != unknown_firewall_name:
                        detected_protections.add(detection.__product__)
                    elif detection.__product__ == unknown_firewall_name:
                        # TODO:/ fingerprint firewall and send it
                        lib.formatter.warn("unknown firewall detected")
                        return
        else:
            lib.formatter.warn("no response was provided, skipping")
    if len(detected_protections) > 0:
        amount_of_products += 1
        if len(detected_protections) > 1:
            for i, _ in enumerate(list(detected_protections)):
                amount_of_products += 1
    if amount_of_products == 1:
        detected_protections = list(detected_protections)[0]
        lib.formatter.success(
            "detected website protection identified as '{}', searching for bypasses".format(detected_protections)
        )
        found_working_tampers = get_working_tampers(
            url, normal_response, payloads, proxy=proxy, agent=agent, verbose=verbose
        )
        lib.settings.produce_results(found_working_tampers)

    elif amount_of_products == 0:
        lib.formatter.success("no protection identified on target")

    else:
        lib.formatter.success("multiple protections identified on target:")
        detected_protections = [item for item in list(detected_protections)]
        for i, protection in enumerate(detected_protections, start=1):
            lib.formatter.success("#{} '{}'".format(i, protection))

        lib.formatter.info("searching for bypasses")
        found_working_tampers = get_working_tampers(
            url, normal_response, payloads, proxy=proxy, agent=agent, verbose=verbose
        )
        lib.settings.produce_results(found_working_tampers)
