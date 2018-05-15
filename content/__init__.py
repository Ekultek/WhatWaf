import os
import re
import json
import importlib
import random

import lib.settings
import lib.formatter
import lib.firewall_found


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
        self.save_fingerprint = kwargs.get("save_fingerprint", False)

    def get_response(self):
        response_retval = []
        strip_url = lambda x: (x.split("/")[0], x.split("/")[2])
        for i, waf_vector in enumerate(self.payloads):
            primary_url = self.url + "{}".format(waf_vector)
            secondary_url = strip_url(self.url)
            secondary_url = "{}//{}".format(secondary_url[0], secondary_url[1])
            secondary_url = "{}/{}".format(secondary_url, random.choice(lib.settings.RAND_HOMEPAGES))
            if self.verbose:
                lib.formatter.payload(waf_vector.strip())
            try:
                if self.verbose:
                    lib.formatter.debug(
                        "trying: '{}'".format(primary_url)
                    )
                response_retval.append((lib.settings.get_page(primary_url, agent=self.agent, proxy=self.proxy)))
                if self.verbose:
                    lib.formatter.debug(
                        "trying: {}".format(secondary_url)
                    )
                response_retval.append((lib.settings.get_page(secondary_url, agent=self.agent, proxy=self.proxy
                )))

            except Exception as e:
                if "ECONNRESET" in str(e):
                    lib.formatter.warn(
                        "possible network level firewall detected (hardware), received an aborted connection"
                    )
                    response_retval.append(None)
                else:
                    lib.formatter.error(
                        "failed to obtain target meta-data with payload {}, error: '{}'".format(
                            waf_vector.strip(), str(e)
                        )
                    )
                    response_retval.append(None)
            if self.save_fingerprint:
                lib.settings.create_fingerprint(
                    self.url, response_retval[0][1], response_retval[0][0], response_retval[0][2], speak=True
                )
        return response_retval


def encode(payload, script):
    """
    encode the payload with the provided tamper
    """
    script = importlib.import_module(script)
    return script.tamper(payload)


def find_failures(html, regs):
    """
    find failures in the response content
    """
    for reg in regs:
        if reg.search(html) is not None or html == "" or html is None:
            return True
    return False


def get_working_tampers(url, norm_response, payloads, **kwargs):
    """
    gather working tamper scripts
    """
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", None)
    verbose = kwargs.get("verbose", False)
    max_successful_payloads = kwargs.get("tamper_int", 5)

    failed_schema = (
        re.compile("404", re.I), re.compile("captcha", re.I),
        re.compile("illegal", re.I), re.compile("blocked", re.I),
        re.compile("ip.logged", re.I), re.compile("ip.address.logged", re.I),
        re.compile("not.acceptable", re.I), re.compile("access.denied", re.I),
        re.compile("forbidden", re.I), re.compile("400", re.I)
    )
    lib.formatter.info("loading payload tampering scripts")
    tampers = ScriptQueue(
        lib.settings.TAMPERS_DIRECTORY, lib.settings.TAMPERS_IMPORT_TEMPLATE, verbose=verbose
    ).load_scripts()

    if max_successful_payloads > len(tampers):
        lib.formatter.warn(
            "the amount of tampers provided is higher than the amount of tampers available, "
            "ALL tampers will be tried (slow!)"
        )
        max_successful_payloads = len(tampers)

    working_tampers = set()
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


def check_if_matched(normal_resp, payload_resp, step=1, verified=5):
    """
    verification that there is not protection on the target
    """
    # five seems like a good number for verification status, you can change it
    # by using the `--verify-num` flag
    matched = 0
    response = set()
    norm_status, norm_html, norm_headers = normal_resp
    payload_status, payload_html, payload_headers = payload_resp
    for header in norm_headers.keys():
        try:
            _ = payload_headers[header]
            matched += step
        except:
            response.add("header values differ when a payload is provided")
    if norm_status == payload_status:
        matched += step
    else:
        response.add("response status code differs when a payload is provided")
    if len(response) != 0:
        if matched <= verified:
            return response
        else:
            return None
    else:
        return None


def dictify_output(url, firewalls, tampers):
    """
    send the output into a JSON format and return the JSON format
    """
    data_sep = "-" * 30
    lib.formatter.info("sending output to JSON format")
    retval = {"url": url}
    if isinstance(firewalls, list):
        retval["identified firewall"] = [item for item in firewalls]
    elif isinstance(firewalls, str):
        retval["identified firewall"] = firewalls
        retval["is protected"] = True
    else:
        retval["identified firewall"] = None
        retval["is protected"] = False

    if len(tampers) != 0:
        retval["apparent working tampers"] = []
        for item in tampers:
            _, _, tamper_script = item
            to_append = str(tamper_script).split(" ")[1].replace("'", "")
            retval["apparent working tampers"].append(to_append)
    else:
        retval["apparent working tampers"] = None

    jsonified = json.dumps(retval, indent=4, sort_keys=True)
    print("{}\n{}\n{}".format(data_sep, jsonified, data_sep))
    return jsonified


def detection_main(url, payloads, **kwargs):
    """
    main detection function
    """
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", lib.settings.DEFAULT_USER_AGENT)
    verbose = kwargs.get("verbose", False)
    skip_bypass_check = kwargs.get("skip_bypass_check", False)
    verification_number = kwargs.get("verification_number", None)
    fingerprint_waf = kwargs.get("fingerprint_waf", False)
    formatted = kwargs.get("formatted", False)
    tamper_int = kwargs.get("tamper_int", 5)
    use_yaml = kwargs.get("use_yaml", False)
    use_json = kwargs.get("use_json", False)
    use_csv = kwargs.get("use_csv", False)

    filepath = lib.settings.YAML_FILE_PATH if use_yaml else lib.settings.JSON_FILE_PATH if use_json else lib.settings.CSV_FILE_PATH
    filename = lib.settings.random_string(length=10, use_yaml=use_yaml, use_json=use_json, use_csv=use_csv)

    # we'll check if the URL has a parameter
    if lib.settings.URL_QUERY_REGEX.search(url) is None:
        # if it doesn't and there is no '/' at the end we're going to add one
        # this should take care of some bugs
        if url[-1] != "/":
            url = url + "/"

    lib.formatter.info("gathering HTTP responses")
    responses = DetectionQueue(
        url, payloads, proxy=proxy, agent=agent, verbose=verbose, save_fingerprint=fingerprint_waf
    ).get_response()
    lib.formatter.info("gathering normal response to compare against")
    normal_response = lib.settings.get_page(url, proxy=proxy, agent=agent)

    amount_of_products = 0
    detected_protections = set()

    lib.formatter.info("loading firewall detection scripts")
    loaded_plugins = ScriptQueue(
        lib.settings.PLUGINS_DIRECTORY, lib.settings.PLUGINS_IMPORT_TEMPLATE, verbose=verbose
    ).load_scripts()

    lib.formatter.info("running firewall detection checks")
    temp = []
    for item in responses:
        item = item if item is not None else normal_response
        if item is not None:
            status, html, headers = item
            for detection in loaded_plugins:
                if detection.detect(str(html), status=status, headers=headers) is True:
                    temp.append(detection.__product__)
                    if detection.__product__ == lib.settings.UNKNOWN_FIREWALL_NAME and len(temp) == 1:
                        lib.formatter.warn("unknown firewall detected saving fingerprint to log file")
                        path = lib.settings.create_fingerprint(url, html, status, headers)
                        lib.firewall_found.request_firewall_issue_creation(path)
                        exit(1)
                    else:
                        detected_protections.add(detection.__product__)
        else:
            lib.formatter.warn("no response was provided, skipping")
    if len(detected_protections) > 0:
        if lib.settings.UNKNOWN_FIREWALL_NAME not in detected_protections:
            amount_of_products += 1
        if len(detected_protections) > 1:
            for i, _ in enumerate(list(detected_protections)):
                amount_of_products += 1
    if amount_of_products == 1:
        detected_protections = list(detected_protections)[0]
        lib.formatter.success(
            "detected website protection identified as '{}', searching for bypasses".format(detected_protections)
        )
        if not skip_bypass_check:
            found_working_tampers = get_working_tampers(
                url, normal_response, payloads, proxy=proxy, agent=agent, verbose=verbose,
                tamper_int=tamper_int
            )
            if not formatted:
                lib.settings.produce_results(found_working_tampers)
            else:
                dict_data_output = dictify_output(url, detected_protections, found_working_tampers)
                written_file_path = lib.settings.write_to_file(
                    filename, filepath, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json
                )
                if written_file_path is not None:
                    lib.formatter.info("data has been written to file: '{}'".format(written_file_path))
        else:
            lib.formatter.warn("skipping bypass checks")
            if formatted:
                dict_data_output = dictify_output(url, detected_protections, [])
                written_file_path = lib.settings.write_to_file(
                    filename, filepath, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json
                )
                if written_file_path is not None:
                    lib.formatter.info("data has been written to file: '{}'".format(written_file_path))

    elif amount_of_products == 0:
        lib.formatter.warn("no protection identified on target, verifying", minor=True)
        if verification_number is None:
            verification_number = 5
        verification_normal_response = lib.settings.get_page(url, proxy=proxy, agent=agent)
        payloaded_url = "{}{}".format(url, lib.settings.WAF_REQUEST_DETECTION_PAYLOADS[3])
        verification_payloaded_response = lib.settings.get_page(payloaded_url, proxy=proxy, agent=agent)
        results = check_if_matched(
            verification_normal_response, verification_payloaded_response,
            verified=verification_number
        )
        if results is not None:
            data_sep = "-" * 30
            lib.formatter.info("target seems to be behind some kind of protection for the following reasons:")
            print(data_sep)
            for i, item in enumerate(results, start=1):
                print("[{}] {}".format(i, item))
            print(data_sep)
            status, html, headers = verification_payloaded_response
            if status != 0:
                path = lib.settings.create_fingerprint(url, html, status, headers)
                lib.firewall_found.request_firewall_issue_creation(path)
            else:
                lib.formatter.warn(
                    "status code returned as `0` meaning that there is no content in the webpage, "
                    "issue will not be created", minor=True
                )
        else:
            lib.formatter.success("no protection identified on target")

    else:
        lib.formatter.success("multiple protections identified on target{}:".format(
            " (unknown firewall will not be displayed)" if lib.settings.UNKNOWN_FIREWALL_NAME in detected_protections else ""
        ))
        detected_protections = [item for item in list(detected_protections)]
        for i, protection in enumerate(detected_protections, start=1):
            if not protection == lib.settings.UNKNOWN_FIREWALL_NAME:
                lib.formatter.success("#{} '{}'".format(i, protection))

        if not skip_bypass_check:
            lib.formatter.info("searching for bypasses")
            found_working_tampers = get_working_tampers(
                url, normal_response, payloads, proxy=proxy, agent=agent, verbose=verbose,
                tamper_int=tamper_int
            )
            if not formatted:
                lib.settings.produce_results(found_working_tampers)
            else:
                dict_data_output = dictify_output(url, detected_protections, found_working_tampers)
                written_file_path = lib.settings.write_to_file(
                    filename, filepath, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json
                )
                if written_file_path is not None:
                    lib.formatter.info("data has been written to file: '{}'".format(written_file_path))
        else:
            lib.formatter.warn("skipping bypass tests")
            if formatted:
                filename = lib.settings.random_string()
                dict_data_output = dictify_output(url, detected_protections, [])
                written_file_path = lib.settings.write_to_file(
                    filename, filepath, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json
                )
                if written_file_path is not None:
                    lib.formatter.info("data has been written to file: '{}'".format(written_file_path))