import os
import re
import json
import importlib
import random
import threading
try:
    import urlparse
except ImportError:
    # python 2.x doesn't have a ModuleNotFoundError so we'll just catch the exception I guess
    import urllib.parse as urlparse
try:
    import queue
except ImportError:
    import Queue as queue
    
import lib.settings
import lib.formatter
import lib.database
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
            try:
                script = importlib.import_module(self.path.format(script))
                retval.append(script)
            except Exception:
                lib.formatter.warn("failed to load tamper '{}', pretending it doesn't exist".format(script))
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
        self.provided_headers = kwargs.get("provided_headers", None)
        self.save_fingerprint = kwargs.get("save_fingerprint", False)
        self.traffic_file = kwargs.get("traffic_file", None)
        self.throttle = kwargs.get("throttle", 0)
        self.req_timeout = kwargs.get("timeout", 15)
        self.request_type = kwargs.get("request_type", "GET")
        self.post_data = kwargs.get("post_data", "")
        self.threads = kwargs.get("threaded", None)
        self.placement = kwargs.get("placement", False)
        self.threading_queue = queue.Queue()
        self.response_retval = []

    def get_response(self):
        response_retval = []
        strip_url = lambda x: (x.split("/")[0], x.split("/")[2])
        for i, waf_vector in enumerate(self.payloads):
            if not self.placement:
                primary_url = self.url + "{}".format(waf_vector)
            else:
                url = self.url.split("*")
                primary_url = "{}{}{}".format(url[0], waf_vector, url[len(url) - 1])
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
                response_retval.append((
                    lib.settings.get_page(
                        primary_url, agent=self.agent, proxy=self.proxy, provided_headers=self.provided_headers,
                        throttle=self.throttle, timeout=self.req_timeout, request_method=self.request_type,
                        post_data=self.post_data
                    )
                ))
                if self.verbose:
                    lib.formatter.debug(
                        "trying: {}".format(secondary_url)
                    )
                response_retval.append((
                    lib.settings.get_page(
                        secondary_url, agent=self.agent, proxy=self.proxy, provided_headers=self.provided_headers,
                        throttle=self.throttle, timeout=self.req_timeout, request_method=self.request_type,
                        post_data=self.post_data
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
                    self.url,
                    response_retval[0][2],
                    response_retval[0][1],
                    response_retval[0][3],
                    req_data=response_retval[0][0],
                    speak=True
                )

        return response_retval

    def threader(self):
        # not sure why this is wrapped in parentheses
        while True:
            url_thread, waf_vector = self.threading_queue.get()
            self.threaded_get_response_helper(url_thread, waf_vector)
            self.threading_queue.task_done()

    def threaded_get_response_helper(self, url_thread, waf_vector):
        try:
            if self.verbose:
                lib.formatter.debug(
                    "trying: '{}'".format(url_thread)
                )
            self.response_retval.append((
                lib.settings.get_page(
                    url_thread, agent=self.agent, proxy=self.proxy, provided_headers=self.provided_headers,
                    throttle=self.throttle, timeout=self.req_timeout, request_method=self.request_type,
                    post_data=self.post_data
                )
            ))

        except Exception as e:
            if "ECONNRESET" in str(e):
                lib.formatter.warn(
                    "possible network level firewall detected (hardware), received an aborted connection"
                )
                self.response_retval.append(None)
            else:
                lib.formatter.error(
                    "failed to obtain target meta-data with payload {}, error: '{}'".format(
                        waf_vector.strip(), str(e)
                    )
                )
                self.response_retval.append(None)

                if self.save_fingerprint:
                    lib.settings.create_fingerprint(
                        self.url,
                        self.response_retval[0][2],
                        self.response_retval[0][1],
                        self.response_retval[0][3],
                        req_data=self.response_retval[0][0],
                        speak=True
                    )

    def threaded_get_response(self):
        strip_url = lambda x: (x.split("/")[0], x.split("/")[2])

        for i, waf_vector in enumerate(self.payloads):
            if not self.placement:
                primary_url = self.url + "{}".format(waf_vector)
            else:
                url = self.url.split("*")
                primary_url = "{}{}{}".format(url[0], waf_vector, url[len(url) - 1])
            secondary_url = strip_url(self.url)
            secondary_url = "{}//{}".format(secondary_url[0], secondary_url[1])
            secondary_url = "{}/{}".format(secondary_url, random.choice(lib.settings.RAND_HOMEPAGES))
            if self.verbose:
                lib.formatter.payload(waf_vector.strip())

            self.threading_queue.put((primary_url, waf_vector))
            self.threading_queue.put((secondary_url, waf_vector))

        for i in range(self.threads):
            t = threading.Thread(target=self.threader)
            t.daemon = True
            t.start()

        self.threading_queue.join()

        return self.response_retval


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
    provided_headers = kwargs.get("provided_headers", None)
    max_successful_payloads = kwargs.get("tamper_int", 5)
    throttle = kwargs.get("throttle", 0)
    req_timeout = kwargs.get("timeout", 15)
    if req_timeout is None:
        lib.formatter.warn(
            "issue occured and the timeout resolved to None, defaulting to 15", minor=True
        )
        req_timeout = 15

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
    _, normal_status, _, _ = norm_response
    lib.formatter.info("running tampering bypass checks")
    for tamper in tampers:
        load = tamper
        if verbose:
            try:
                lib.formatter.debug("currently tampering with script '{}".format(str(load).split(" ")[1].split(".")[-1]))
            except:
                pass
        for vector in payloads:
            vector = tamper.tamper(vector)
            if verbose:
                lib.formatter.payload(vector.strip())
            payloaded_url = "{}{}".format(url, vector)
            _, status, html, _ = lib.settings.get_page(
                payloaded_url, agent=agent, proxy=proxy, verbose=verbose, provided_headers=provided_headers,
                throttle=throttle, timeout=req_timeout
            )
            if not find_failures(str(html), failed_schema):
                if verbose:
                    if status != 0:
                        lib.formatter.debug("response code: {}".format(status))
                    else:
                        lib.formatter.debug("unknown response detected")
                if status != 404:
                    if status == 200:
                        try:
                            working_tampers.add((tamper.__type__, tamper.tamper(tamper.__example_payload__), load))
                        except:
                            pass
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
    _, norm_status, norm_html, norm_headers = normal_resp
    _, payload_status, payload_html, payload_headers = payload_resp
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
    lib.formatter.info("formatting output")
    retval = {"url": url}
    if isinstance(firewalls, list):
        retval["identified firewall"] = [item for item in firewalls]
        retval["is protected"] = True
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


def detection_main(url, payloads, cursor, **kwargs):
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
    provided_headers = kwargs.get("provided_headers", None)
    traffic_file = kwargs.get("traffic_file", None)
    throttle = kwargs.get("throttle", 0)
    req_timeout = kwargs.get("req_timeout", 15)
    request_type = kwargs.get("request_type", "GET")
    post_data = kwargs.get("post_data", "")
    check_server = kwargs.get("check_server", False)
    threaded = kwargs.get("threaded", None)
    force_file_creation = kwargs.get("force_file_creation", False)
    save_file_copy_path = kwargs.get("save_copy_of_file", None)

    current_url_netloc = urlparse.urlparse(url).netloc

    if lib.settings.URL_QUERY_REGEX.search(str(url)) is None:
        lib.formatter.warn(
            "URL does not appear to have a query (parameter), this may interfere with the detection results",
            minor=True
        )

    __check_custom_placement = lambda u: "*" in u
    if __check_custom_placement(url):
        choice = lib.formatter.prompt(
            "custom placement marker found in URL `*` would you like to use it to place the attacks", "yN"
        )
        if choice.lower().startswith("y"):
            use_placement = True
        else:
            use_placement = False
    else:
        use_placement = False

    filepath = lib.settings.YAML_FILE_PATH if use_yaml else lib.settings.JSON_FILE_PATH if use_json else lib.settings.CSV_FILE_PATH
    try:
        if "http" in url:
            file_start = url.split("/")[2].split(".")[1]
        else:
            file_start = url.split(".")[1]
        if use_json:
            ext = ".json"
        elif use_yaml:
            ext = ".yaml"
        elif use_csv:
            ext = ".csv"
        filename = "{}{}".format(file_start, ext)
    except:
        filename = lib.settings.random_string(length=10, use_yaml=use_yaml, use_json=use_json, use_csv=use_csv)

    lib.formatter.info("request type: {}".format(request_type))

    if post_data is None:
        post_data = ""

    if post_data is not None and post_data != "":
        lib.formatter.info("POST string to be sent: '{}'".format(post_data))
    elif request_type == "POST":
        if len(post_data) == 0:
            lib.formatter.warn("no POST string supplied generating random", minor=True)
            post_data = lib.settings.generate_random_post_string()
            lib.formatter.info("random POST string to be sent: '{}'".format(post_data))

    if lib.settings.validate_url(url) is None:
        raise lib.settings.InvalidURLProvided

    # we'll check if the URL has a parameter
    if lib.settings.URL_QUERY_REGEX.search(url) is None:
        # if it doesn't and there is no '/' at the end we're going to add one
        # this should take care of some bugs
        if url[-1] != "/":
            url = url + "/"

    lib.formatter.info("gathering HTTP responses")
    if not threaded:
        responses = DetectionQueue(
            url, payloads, proxy=proxy, agent=agent, verbose=verbose, save_fingerprint=fingerprint_waf,
            provided_headers=provided_headers, traffic_file=traffic_file, throttle=throttle,
            timeout=req_timeout, request_type=request_type, post_data=post_data, placement=use_placement
        ).get_response()
    elif threaded:
        responses = DetectionQueue(
            url, payloads, proxy=proxy, agent=agent, verbose=verbose, save_fingerprint=fingerprint_waf,
            provided_headers=provided_headers, traffic_file=traffic_file, throttle=throttle,
            timeout=req_timeout, request_type=request_type, post_data=post_data, threaded=threaded,
            placement=use_placement
        ).threaded_get_response()
    if traffic_file is not None:
        with open(traffic_file, "a+") as traffic:
            for i, item in enumerate(responses, start=1):
                param, status_code, content, headers = item
                traffic.write(
                    "HTTP Request #{}\n{}\nRequest Status Code: {}\n<!--\n{} HTTP/1.1\n{}\n-->{}\n\n\n".format(
                        i, "-" * 16, status_code, param,
                        "\n".join(["{}: {}".format(h, v) for h, v in headers.items()]),
                        content
                    )
                )

    lib.formatter.info("gathering normal response to compare against")
    normal_response = lib.settings.get_page(
        url, proxy=proxy, agent=agent, provided_headers=provided_headers, throttle=throttle,
        timeout=req_timeout, request_method=request_type, post_data=post_data
    )

    if check_server:
        found = None
        for resp in responses:
            headers = resp[-1]
        for k in headers.keys():
            if k.lower() == "server":
                found = headers[k]
                break
        if found is None:
            lib.formatter.warn("unable to determine web server")
        else:
            lib.formatter.success("web server determined as: {}".format(found))
        found_webserver = found
    else:
        found_webserver = None

    # plus one for lib.settings.get_page call
    request_count = len(responses) + 1
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
        _, status, html, headers = item
        for detection in loaded_plugins:
            try:
                if detection.detect(str(html), status=status, headers=headers) is True:
                    temp.append(detection.__product__)
                    if detection.__product__ == lib.settings.UNKNOWN_FIREWALL_NAME and len(temp) == 1 and status != 0:
                        lib.formatter.warn("unknown firewall detected saving fingerprint to log file")
                        path = lib.settings.create_fingerprint(url, html, status, headers)
                        return lib.firewall_found.request_firewall_issue_creation(path)
                    else:
                        detected_protections.add(detection.__product__)
            except Exception:
                pass
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
                tamper_int=tamper_int, provided_headers=provided_headers, throttle=throttle,
                timeout=req_timeout
            )
            if not formatted:
                lib.settings.produce_results(found_working_tampers)
            else:
                dict_data_output = dictify_output(url, detected_protections, found_working_tampers)
                written_file_path = lib.settings.write_to_file(
                    filename, filepath, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                    save_copy_to=save_file_copy_path
                )
                if written_file_path is not None:
                    lib.formatter.info("data has been written to file: '{}'".format(written_file_path))
            inserted_into_database_results = lib.database.insert_url(
                current_url_netloc, found_working_tampers, detected_protections, cursor, webserver=found_webserver
            )
        else:
            lib.formatter.warn("skipping bypass checks")
            if formatted:
                dict_data_output = dictify_output(url, detected_protections, [])
                written_file_path = lib.settings.write_to_file(
                    filename, filepath, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                    save_copy_to=save_file_copy_path
                )
                if written_file_path is not None:
                    lib.formatter.info("data has been written to file: '{}'".format(written_file_path))
            if isinstance(detected_protections, str):
                detected_protections = [detected_protections]
            inserted_into_database_results = lib.database.insert_url(
                current_url_netloc, [], detected_protections, cursor, webserver=found_webserver
            )

    elif amount_of_products == 0:
        lib.formatter.warn("no protection identified on target, verifying", minor=True)
        if verification_number is None:
            verification_number = 5
        verification_normal_response = lib.settings.get_page(
            url, proxy=proxy, agent=agent, provided_headers=provided_headers, throttle=throttle,
            timeout=req_timeout, request_method=request_type, post_data=post_data
        )
        payloaded_url = "{}{}".format(url, lib.settings.WAF_REQUEST_DETECTION_PAYLOADS[3])
        verification_payloaded_response = lib.settings.get_page(
            payloaded_url, proxy=proxy, agent=agent, provided_headers=provided_headers, throttle=throttle,
            timeout=req_timeout, request_method=request_type, post_data=post_data
        )
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
            _, status, html, headers = verification_payloaded_response
            if status != 0:
                path = lib.settings.create_fingerprint(url, html, status, headers)
                lib.firewall_found.request_firewall_issue_creation(path)
            else:
                lib.formatter.warn(
                    "status code returned as `0` meaning that there is no content in the webpage, "
                    "issue will not be created", minor=True
                )
            inserted_into_database_results = lib.database.insert_url(
                current_url_netloc, [], [], cursor, webserver=found_webserver
            )
        else:
            lib.formatter.success("no protection identified on target")
            if formatted:
                if not force_file_creation:
                    lib.formatter.warn(
                        "no data will be written to files since no protection could be identified, "
                        "to force file creation pass the `--force-file` argument"
                    )
                else:
                    # if the argument `--force-file` is passed we will create the file
                    # anyways, this should give users who are relying on the JSON files
                    # for thirdparty information a chance to get the data out of the directory
                    # then they can easily parse it without problems.
                    lib.formatter.warn("forcing file creation without successful identification", minor=True)
                    dict_data_output = dictify_output(url, None, [])
                    written_file_path = lib.settings.write_to_file(
                        filename, filepath, dict_data_output,
                        write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                        save_copy_to=save_file_copy_path
                    )
                    if written_file_path is not None:
                        lib.formatter.info("data has been written to file: '{}'".format(written_file_path))
            inserted_into_database_results = lib.database.insert_url(
                current_url_netloc, [], [], cursor, webserver=found_webserver
            )

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
                tamper_int=tamper_int, throttle=throttle, timeout=req_timeout, provided_headers=provided_headers
            )
            if not formatted:
                lib.settings.produce_results(found_working_tampers)
            else:
                dict_data_output = dictify_output(url, detected_protections, found_working_tampers)
                written_file_path = lib.settings.write_to_file(
                    filename, filepath, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                    save_copy_to=save_file_copy_path
                )
                if written_file_path is not None:
                    lib.formatter.info("data has been written to file: '{}'".format(written_file_path))
            inserted_into_database_results = lib.database.insert_url(
                current_url_netloc, found_working_tampers, detected_protections, cursor, webserver=found_webserver
            )
        else:
            lib.formatter.warn("skipping bypass tests")
            if formatted:
                dict_data_output = dictify_output(url, detected_protections, [])
                written_file_path = lib.settings.write_to_file(
                    filename, filepath, dict_data_output,
                    write_csv=use_csv, write_yaml=use_yaml, write_json=use_json,
                    save_copy_to=save_file_copy_path
                )
                if written_file_path is not None:
                    lib.formatter.info("data has been written to file: '{}'".format(written_file_path))
            inserted_into_database_results = lib.database.insert_url(
                current_url_netloc, [], detected_protections, cursor, webserver=found_webserver
            )
    if inserted_into_database_results:
        lib.formatter.info("URL has been cached for future use")

    return request_count
