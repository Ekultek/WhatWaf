import sys
import time
import shlex
import subprocess

from lib.cmd import WhatWafParser
from lib.firewall_found import request_issue_creation
from content import (
    detection_main,
    encode
)
from lib.settings import (
    configure_request_headers,
    auto_assign,
    get_page,
    WAF_REQUEST_DETECTION_PAYLOADS,
    BANNER,
    HOME,
    InvalidURLProvided,
    parse_burp_request,
    parse_googler_file,
    check_version,
    get_encoding_list,
    test_target_connection,
    parse_help_menu,
    export_payloads,
    PLUGINS_DIRECTORY,
    TAMPERS_DIRECTORY,
    check_url_against_cached,
    RESULTS_TEMPLATE
)
from lib.formatter import (
    error,
    info,
    fatal,
    warn,
    success
)
from lib.database import (
    initialize,
    insert_payload,
    fetch_data
)


try:
    raw_input
except Exception:
    raw_input = input


def main():
    opt = WhatWafParser().cmd_parser()

    if not len(sys.argv) > 1:
        error("you failed to provide an option, redirecting to help menu")
        time.sleep(2)
        cmd = "python whatwaf.py --help"
        subprocess.call(shlex.split(cmd))
        exit(0)

    # if you feel that you have to many folders or files in the whatwaf home folder
    # we'll give you an option to clean it free of charge
    if opt.cleanHomeFolder:
        import shutil

        try:
            warn(
                "cleaning the home folder: {home}, if you have installed with setup.sh, "
                "this will erase the executable script along with everything inside "
                "of the {home} directory (fingerprints, scripts, copies of whatwaf, etc) "
                "if you are sure you want to do this press ENTER now. If you changed "
                "your mind press CNTRL-C now".format(home=HOME)
            )
            # you have three seconds to change your mind
            raw_input("")
            info("attempting to clean home folder")
            shutil.rmtree(HOME)
            info("home folder removed")
        except KeyboardInterrupt:
            fatal("cleaning aborted")
        except OSError:
            fatal("no home folder detected, already cleaned?")
        exit(0)

    cursor = initialize()

    if opt.exportEncodedToFile is not None:
        payloads = fetch_data(cursor)
        if len(payloads) != 0:
            exported_payloads_path = export_payloads(payloads, opt.exportEncodedToFile)
            info("payloads exported to: {}".format(exported_payloads_path))
        else:
            warn(
                "there appears to be no payloads stored in the database, to create payloads use the following options:"
            )
            proc = subprocess.check_output(["python", "whatwaf.py", "--help"])
            parsed_help = parse_help_menu(str(proc), "encoding options:", "output options:")
            print(parsed_help)
        exit(1)

    if opt.viewAllCache:
        cached_payloads = fetch_data(cursor)
        cached_urls = fetch_data(cursor, is_payload=False)
        if len(cached_urls) != 0:
            info("total of {} URL(s) currently cached".format(len(cached_urls)))
            for i, item in enumerate(cached_urls, start=1):
                id_num, netlock, prots, tamps, server = item
                print(
                    "URL #{} '{}':\nProtections: {}\nTampers: {}\nWebserver: {}\n{}".format(
                        id_num, netlock, prots, tamps, server, "-" * 20
                    )
                )
                if i % 200 == 0:
                    raw_input("\npress enter to continue...\n")
        else:
            warn("no URLs have been cached yet")
        if len(cached_payloads) != 0:
            info("total of {} payload(s) cached".format(len(cached_payloads)))
            for i, payload in enumerate(cached_payloads, start=1):
                if i % 200 == 0:
                    raw_input("\npress enter to continue...\n")
                print("#{}  {}".format(payload[0], payload[1]))
        else:
            warn("no payloads have been cached yet")
        exit(0)

    if opt.viewCachedPayloads:
        payloads = fetch_data(cursor)
        if len(payloads) != 0:
            info("total of {} payload(s) cached".format(len(payloads)))
            for i, payload in enumerate(payloads, start=1):
                if i % 200 == 0:
                    raw_input("\npress enter to continue...\n")
                print("#{}  {}".format(payload[0], payload[1]))
        else:
            warn(
                "there appears to be no payloads stored in the database, to create payloads use the following options:"
            )
            proc = subprocess.check_output(["python", "whatwaf.py", "--help"])
            parsed_help = parse_help_menu(proc, "encoding options:", "output options:")
            print(parsed_help)
        exit(0)

    if opt.encodePayload is not None:
        spacer = "-" * 30
        payload = opt.encodePayload[0]
        load_path = opt.encodePayload[1:]
        for load in load_path:
            try:
                payload = encode(payload, load)
            except (AttributeError, ImportError):
                warn("invalid load path given: '{}', skipping it and continuing".format(load))
        success("encoded successfully:")
        print(
            "{}\n{}\n{}".format(
                spacer, payload, spacer
            )
        )
        insert_payload(payload, cursor)
        info("payload has been cached for future use")
        exit(0)

    if opt.encodePayloadList is not None:
        spacer = "-" * 30
        try:
            file_path, load_path = opt.encodePayloadList
            info("encoding payloads from given file '{}' using given tamper '{}'".format(
                file_path, load_path
            ))
            with open(file_path) as payloads:
                encoded = [encode(p.strip(), load_path) for p in payloads.readlines()]
                if opt.saveEncodedPayloads is not None:
                    with open(opt.saveEncodedPayloads, "a+") as save:
                        for item in encoded:
                            save.write(item + "\n")
                    success("saved encoded payloads to file '{}' successfully".format(opt.saveEncodedPayloads))
                else:
                    success("payloads encoded successfully:")
                    print(spacer)
                    for i, item in enumerate(encoded, start=1):
                        insert_payload(item, cursor)
                        print(
                            "#{} {}".format(i, item)
                        )
                    print(spacer)
            info("payloads have been cached for future use")
        except IOError:
            fatal("provided file '{}' appears to not exist, check the path and try again".format(file_path))
        except (AttributeError, ImportError):
            fatal("invalid load path given, check the load path and try again")
        exit(0)

    if opt.updateWhatWaf:
        info("update in progress")
        cmd = shlex.split("git pull origin master")
        subprocess.call(cmd)
        exit(0)

    if not opt.hideBanner:
        print(BANNER)

    if opt.listEncodingTechniques:
        info("gathering available tamper script load paths")
        tamper_list = get_encoding_list(TAMPERS_DIRECTORY, is_tampers=True, is_wafs=False)
        for tamper in sorted(tamper_list):
            print(tamper)
        exit(0)

    if opt.viewPossibleWafs:
        import importlib

        info("gathering a list of possible detectable wafs")
        wafs_list = get_encoding_list(PLUGINS_DIRECTORY, is_tampers=False, is_wafs=True)
        for i, waf in enumerate(wafs_list, start=1):
            try:
                imported = importlib.import_module(waf)
                print("{}".format(imported.__product__))
            except ImportError:
                pass
        exit(0)

    info("checking for updates")
    check_version()

    format_opts = [opt.sendToYAML, opt.sendToCSV, opt.sendToJSON]
    if opt.formatOutput:
        amount_used = 0
        for item in format_opts:
            if item is True:
                amount_used += 1
        if amount_used > 1:
            warn(
                "multiple file formats have been detected, there is a high probability that this will cause "
                "issues while saving file information. please use only one format at a time"
            )
        elif amount_used == 0:
            warn(
                "output will not be saved to a file as no file format was provided. to save output to file "
                "pass one of the file format flags (IE `-J` for JSON format)", minor=True
            )
    elif any(format_opts) and not opt.formatOutput:
        warn(
            "you've chosen to send the output to a file, but have not formatted the output, no file will be saved "
            "do so by passing the format flag (IE `-F -J` for JSON format)"
        )

    if opt.skipBypassChecks and opt.amountOfTampersToDisplay is not None:
        warn(
            "you've chosen to skip bypass checks and chosen an amount of tamper to display, tampers will be skipped",
            minor=True
        )

    # there is an extra dependency that you need in order
    # for requests to run behind socks proxies, we'll just
    # do a little check to make sure you have it installed
    if opt.runBehindTor or opt.runBehindProxy is not None and "socks" in opt.runBehindProxy:
        try:
            import socks
        except ImportError:
            # if you don't we will go ahead and exit the system with an error message
            error(
                "to run behind socks proxies (like Tor) you need to install pysocks `pip install pysocks`, "
                "otherwise use a different proxy protocol"
            )
            sys.exit(1)

    proxy, agent = configure_request_headers(
        random_agent=opt.useRandomAgent, agent=opt.usePersonalAgent,
        proxy=opt.runBehindProxy, tor=opt.runBehindTor, tor_port=opt.configTorPort
    )

    if opt.checkTorConnection:
        import re

        info("checking Tor connection")
        check_url = "https://check.torproject.org/"
        check_regex = re.compile("This browser is configured to use Tor.", re.I)
        _, _, content, _ = get_page(check_url, proxy=proxy, agent=agent)
        if check_regex.search(str(content)) is not None:
            success("it appears that Tor is working properly")
        else:
            warn("it appears Tor is not configured properly")

    if opt.providedPayloads is not None:
        payload_list = [p.strip() if p[0] == " " else p for p in str(opt.providedPayloads).split(",")]
        info("using provided payloads")
    elif opt.payloadList is not None:
        try:
            open(opt.payloadList).close()
        except Exception:
            fatal("provided file '{}' does not exists, check the path and try again".format(opt.payloadList))
            exit(1)
        payload_list = [p.strip("\n") for p in open(opt.payloadList).readlines()]
        info("using provided payload file '{}'".format(opt.payloadList))
    else:
        payload_list = WAF_REQUEST_DETECTION_PAYLOADS
        info("using default payloads")

    if opt.saveFingerprints:
        warn(
            "fingerprinting is enabled, all fingerprints (WAF related or not) will be saved for further analysis "
            "if the fingerprint already exists it will be skipped",
            minor=True
        )

    if opt.trafficFile is not None:
        info("saving HTTP traffic to '{}'".format(opt.trafficFile))
    if opt.sleepTimeThrottle != 0:
        info("sleep throttle has been set to {}s".format(opt.sleepTimeThrottle))

    try:
        if opt.postRequest:
            request_type = "POST"
        else:
            request_type = "GET"

        request_count = 0

        if opt.runSingleWebsite:
            url_to_use = auto_assign(opt.runSingleWebsite, ssl=opt.forceSSL)
            if opt.checkCachedUrls:
                checked_results = check_url_against_cached(url_to_use, cursor)
                if checked_results is not None:
                    print(
                        RESULTS_TEMPLATE.format(
                            "-" * 20,
                            str(checked_results[1]),
                            str(checked_results[2]),
                            str(checked_results[3]),
                            str(checked_results[4]),
                            "-" * 20
                        )
                    )
                    exit(0)

            if opt.testTargetConnection:
                info("testing connection to target URL before starting attack")
                results = test_target_connection(url_to_use, proxy=proxy, agent=agent, headers=opt.extraHeaders)
                if results == "nogo":
                    fatal("connection to target URL failed multiple times, check connection and try again")
                    exit(1)
                elif results == "acceptable":
                    warn(
                        "there appears to be some latency on the connection, this may interfere with results",
                        minor=False
                    )
                else:
                    success("connection succeeded, continuing")

            info("running single web application '{}'".format(url_to_use))
            requests = detection_main(
                url_to_use, payload_list, cursor, agent=agent, proxy=proxy,
                verbose=opt.runInVerbose, skip_bypass_check=opt.skipBypassChecks,
                verification_number=opt.verifyNumber, formatted=opt.formatOutput,
                tamper_int=opt.amountOfTampersToDisplay, use_json=opt.sendToJSON,
                use_yaml=opt.sendToYAML, use_csv=opt.sendToCSV,
                fingerprint_waf=opt.saveFingerprints, provided_headers=opt.extraHeaders,
                traffic_file=opt.trafficFile, throttle=opt.sleepTimeThrottle,
                req_timeout=opt.requestTimeout, post_data=opt.postRequestData,
                request_type=request_type, check_server=opt.determineWebServer,
                threaded=opt.threaded, force_file_creation=opt.forceFileCreation,
                save_copy_of_file=opt.outputDirectory
            )
            request_count = request_count + requests if requests is not None else request_count
        elif any(o is not None for o in [opt.runMultipleWebsites, opt.burpRequestFile]):
            info("reading from '{}'".format(opt.runMultipleWebsites or opt.burpRequestFile))
            try:
                open(opt.runMultipleWebsites or opt.burpRequestFile)
            except IOError:
                fatal("file: '{}' did not open, does it exist?".format(opt.runMultipleWebsites))
                exit(-1)
            if opt.runMultipleWebsites is not None:
                site_runners = []
                with open(opt.runMultipleWebsites) as urls:
                    for url in urls:
                        possible_url = auto_assign(url.strip(), ssl=opt.forceSSL)
                        if opt.checkCachedUrls:
                            url_is_cached = check_url_against_cached(possible_url, cursor)
                            if url_is_cached is not None:
                                print(
                                    RESULTS_TEMPLATE.format(
                                        "-" * 20,
                                        str(url_is_cached[1]),
                                        str(url_is_cached[2]),
                                        str(url_is_cached[3]),
                                        str(url_is_cached[4]),
                                        "-" * 20
                                    )
                                )
                            else:
                                site_runners.append(possible_url)
                        else:
                            site_runners.append(possible_url)
            elif opt.burpRequestFile is not None:
                site_runners = parse_burp_request(opt.burpRequestFile)
            else:
                site_runners = []

            if len(site_runners) == 0:
                fatal("no targets parsed from file, exiting")
                exit(1)
            else:
                info("parsed a total of {} target(s) from file".format(len(site_runners)))

            for i, url in enumerate(site_runners, start=1):
                if opt.testTargetConnection:
                    info("testing connection to target URL before starting attack")
                    results = test_target_connection(url, proxy=proxy, agent=agent, headers=opt.extraHeaders)
                    if results == "nogo":
                        fatal("connection to target URL failed multiple times, check connection and try again")
                        exit(1)
                    elif results == "acceptable":
                        warn(
                            "there appears to be some latency on the connection, this may interfere with results",
                            minor=False
                        )
                    else:
                        success("connection succeeded, continuing")

                info("currently running on site #{} ('{}')".format(i, url))
                requests = detection_main(
                    url, payload_list, cursor, agent=agent, proxy=proxy,
                    verbose=opt.runInVerbose, skip_bypass_check=opt.skipBypassChecks,
                    verification_number=opt.verifyNumber, formatted=opt.formatOutput,
                    tamper_int=opt.amountOfTampersToDisplay, use_json=opt.sendToJSON,
                    use_yaml=opt.sendToYAML, use_csv=opt.sendToCSV,
                    fingerprint_waf=opt.saveFingerprints, provided_headers=opt.extraHeaders,
                    traffic_file=opt.trafficFile, throttle=opt.sleepTimeThrottle,
                    req_timeout=opt.requestTimeout, post_data=opt.postRequestData,
                    request_type=request_type, check_server=opt.determineWebServer,
                    threaded=opt.threaded, force_file_creation=opt.forceFileCreation,
                    save_copy_of_file=opt.outputDirectory
                )
                request_count = request_count + requests if requests is not None else request_count
                print("\n\b")
                time.sleep(0.5)

        elif opt.googlerFile is not None:
            urls = parse_googler_file(opt.googlerFile)
            if urls is not None:
                info("parsed a total of {} URLS from Googler JSON file".format(len(urls)))
                for i, url in enumerate(urls, start=1):
                    do_url_run = True
                    if opt.checkCachedUrls:
                        url_is_cached = check_url_against_cached(url, cursor)
                        if url_is_cached is not None:
                            print(
                                RESULTS_TEMPLATE.format(
                                    "-" * 20,
                                    str(url_is_cached[1]),
                                    str(url_is_cached[2]),
                                    str(url_is_cached[3]),
                                    str(url_is_cached[4]),
                                    "-" * 20
                                )
                            )
                            do_url_run = False

                    if do_url_run:
                        if opt.testTargetConnection:
                            info("testing connection to target URL before starting attack")
                            results = test_target_connection(url, proxy=proxy, agent=agent, headers=opt.extraHeaders)
                            if results == "nogo":
                                fatal("connection to target URL failed multiple times, check connection and try again")
                                exit(1)
                            elif results == "acceptable":
                                warn(
                                    "there appears to be some latency on the connection, this may interfere with results",
                                    minor=False
                                )
                            else:
                                success("connection succeeded, continuing")

                        info("currently running on '{}' (site #{})".format(url, i))
                        requests = detection_main(
                            url, payload_list, cursor, agent=agent, proxy=proxy,
                            verbose=opt.runInVerbose, skip_bypass_check=opt.skipBypassChecks,
                            verification_number=opt.verifyNumber, formatted=opt.formatOutput,
                            tamper_int=opt.amountOfTampersToDisplay, use_json=opt.sendToJSON,
                            use_yaml=opt.sendToYAML, use_csv=opt.sendToCSV,
                            fingerprint_waf=opt.saveFingerprints, provided_headers=opt.extraHeaders,
                            traffic_file=opt.trafficFile, throttle=opt.sleepTimeThrottle,
                            req_timeout=opt.requestTimeout, post_data=opt.postRequestData,
                            request_type=request_type, check_server=opt.determineWebServer,
                            threaded=opt.threaded, force_file_creation=opt.forceFileCreation,
                            save_copy_of_file=opt.outputDirectory
                        )
                        request_count = request_count + requests if requests is not None else request_count
                        print("\n\b")
                        time.sleep(0.5)
            else:
                fatal("file failed to load, does it exist?")

        if request_count != 0:
            info("total requests sent: {}".format(request_count))
        else:
            warn("request counter failed to count correctly, deactivating", minor=True)

    except KeyboardInterrupt:
        fatal("user aborted scanning")
    except InvalidURLProvided:
        fatal(
            "the provided URL is unable to be validated, check the URL and try again (you may need to unquote the "
            "HTML entities)"
        )
    except Exception as e:
        import traceback

        sep = "-" * 30
        fatal(
            "WhatWaf has caught an unhandled exception with the error message: '{}'.".format(str(e))
        )
        exception_data = "Traceback (most recent call):\n{}{}".format(
            "".join(traceback.format_tb(sys.exc_info()[2])), str(e)
        )
        error(
            "\n{}\n{}\n{}".format(
                sep, exception_data, sep
            )
        )
        request_issue_creation(exception_data)

