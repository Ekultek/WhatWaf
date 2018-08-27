import sys
import time
import shlex
import subprocess

from lib.cmd import WhatWafParser
from lib.firewall_found import hide_sensitive
from content import (
    detection_main,
    encode
)
from lib.settings import (
    configure_request_headers,
    auto_assign,
    get_page,
    WAF_REQUEST_DETECTION_PAYLOADS,
    BANNER, HOME, ISSUES_LINK,
    InvalidURLProvided, VERSION,
    parse_burp_request,
    check_version
)
from lib.formatter import (
    error,
    info,
    fatal,
    warn,
    success
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
                "cleaning home folder, all information will be deleted, if you changed your mind press CNTRL-C now, "
                "otherwise hit enter to continue"
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

    if opt.encodePayload:
        spacer = "-" * 30
        payload, load_path = opt.encodePayload
        info("encoding '{}' using '{}'".format(payload, load_path))
        try:
            encoded = encode(payload, load_path)
            success("encoded successfully:")
            print(
                "{}\n{}\n{}".format(
                    spacer, encoded, spacer
                )
            )
        except (AttributeError, ImportError):
            fatal("invalid load path given, check the load path and try again")
        exit(0)

    if opt.encodePayloadList:
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
                        print(
                            "#{} {}".format(i, item)
                        )
                    print(spacer)
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
        proxy=opt.runBehindProxy, tor=opt.runBehindTor
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
            info("running single web application '{}'".format(url_to_use))
            requests = detection_main(
                url_to_use, payload_list, agent=agent, proxy=proxy,
                verbose=opt.runInVerbose, skip_bypass_check=opt.skipBypassChecks,
                verification_number=opt.verifyNumber, formatted=opt.formatOutput,
                tamper_int=opt.amountOfTampersToDisplay, use_json=opt.sendToJSON,
                use_yaml=opt.sendToYAML, use_csv=opt.sendToCSV,
                fingerprint_waf=opt.saveFingerprints, provided_headers=opt.extraHeaders,
                traffic_file=opt.trafficFile, throttle=opt.sleepTimeThrottle,
                req_timeout=opt.requestTimeout, post_data=opt.postRequestData,
                request_type=request_type, check_server=opt.determineWebServer,
                threaded=opt.threaded
            )
            request_count = request_count + requests if requests is not None else request_count
        elif opt.runMultipleWebsites:
            info("reading from '{}'".format(opt.runMultipleWebsites))
            try:
                open(opt.runMultipleWebsites)
            except IOError:
                fatal("file: '{}' did not open, does it exist?".format(opt.runMultipleWebsites))
                exit(-1)
            with open(opt.runMultipleWebsites) as urls:
                for i, url in enumerate(urls, start=1):
                    url = auto_assign(url.strip(), ssl=opt.forceSSL)
                    info("currently running on site #{} ('{}')".format(i, url))
                    requests = detection_main(
                        url, payload_list, agent=agent, proxy=proxy,
                        verbose=opt.runInVerbose, skip_bypass_check=opt.skipBypassChecks,
                        verification_number=opt.verifyNumber, formatted=opt.formatOutput,
                        tamper_int=opt.amountOfTampersToDisplay, use_json=opt.sendToJSON,
                        use_yaml=opt.sendToYAML, use_csv=opt.sendToCSV,
                        fingerprint_waf=opt.saveFingerprints, provided_headers=opt.extraHeaders,
                        traffic_file=opt.trafficFile, throttle=opt.sleepTimeThrottle,
                        req_timeout=opt.requestTimeout, post_data=opt.postRequestData,
                        request_type=request_type, check_server=opt.determineWebServer,
                        threaded=opt.threaded
                    )
                    request_count = request_count + requests if requests is not None else request_count
                    print("\n\b")
                    time.sleep(0.5)

        elif opt.burpRequestFile:
            request_data = parse_burp_request(opt.burpRequestFile)
            info("URL parsed from request file: '{}'".format(request_data["base_url"]))
            requests = detection_main(
                request_data["base_url"], payload_list,
                verbose=opt.runInVerbose, skip_bypass_check=opt.skipBypassChecks,
                verification_number=opt.verifyNumber, formatted=opt.formatOutput,
                tamper_int=opt.amountOfTampersToDisplay, use_json=opt.sendToJSON,
                use_yaml=opt.sendToYAML, use_csv=opt.sendToCSV,
                fingerprint_waf=opt.saveFingerprints, provided_headers=request_data["request_headers"],
                traffic_file=opt.trafficFile, throttle=opt.sleepTimeThrottle,
                req_timeout=opt.requestTimeout, post_data=request_data["post_data"],
                request_type=request_data["request_method"], check_server=opt.determineWebServer,
                threaded=opt.threaded
            )
            request_count = request_count + requests if requests is not None else request_count

        info("total requests sent: {}".format(request_count))

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
            "WhatWaf has caught an unhandled exception with the error message: '{}'. "
            "You can create an issue here: '{}'".format(
                str(e), ISSUES_LINK
            )
        )
        warn("you will need the following information to create an issue:")
        print(
            "{}\nTraceback:\n```\n{}```\nCMD line: `{}`\nVersion: `{}`\n{}".format(
                sep, "".join(traceback.format_tb(sys.exc_info()[2])), hide_sensitive(sys.argv, "-u"),
                VERSION, sep
            )
        )
