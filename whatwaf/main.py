import sys
import shlex
import time
import subprocess

from lib.cmd import WhatWafParser
from content import (
    detection_main,
    encode
)
from lib.settings import (
    configure_request_headers,
    WAF_REQUEST_DETECTION_PAYLOADS,
    BANNER,
    PROTOCOL_DETECTION
)
from lib.formatter import (
    error,
    info,
    fatal
)


def main():
    opt = WhatWafParser().cmd_parser()

    if not len(sys.argv) > 1:
        error("you failed to provide an option, redirecting to help menu")
        time.sleep(2)
        cmd = "python whatwaf.py --help"
        subprocess.call(shlex.split(cmd))
        exit(0)

    if opt.encodePayload:
        spacer = "-" * 30
        info("encoding '{}' using '{}'".format(opt.encodePayload[0], opt.encodePayload[1]))
        try:
            encoded = encode(opt.encodePayload[0], opt.encodePayload[1])
            print(
                "{}\n{}\n{}".format(
                    spacer, encoded, spacer
                )
            )
        except AttributeError:
            error("invalid load path given, check the load path and try again")
        exit(0)

    if opt.updateWhatWaf:
        info("update in progress")
        cmd = shlex.split("git pull origin master")
        subprocess.call(cmd)
        exit(0)

    if not opt.hideBanner:
        print(BANNER)

    proxy, agent = configure_request_headers(
        random_agent=opt.useRandomAgent, agent=opt.usePersonalAgent,
        proxy=opt.runBehindProxy, tor=opt.runBehindTor
    )

    if opt.providedPayloads is not None:
        payload_list = [p.strip() if p[0] == " " else p for p in str(opt.providedPayloads).split(",")]
        info("using provided payloads")
    elif opt.payloadList is not None:
        payload_list = [p.strip("\n") for p in open(opt.payloadList).readlines()]
        info("using provided payload file '{}'".format(opt.payloadList))
    else:
        payload_list = WAF_REQUEST_DETECTION_PAYLOADS
        info("using default payloads")

    try:
        if opt.runSingleWebsite:
            if PROTOCOL_DETECTION.search(opt.runSingleWebsite) is None:
                opt.runSingleWebsite = "http://{}".format(opt.runSingleWebsite)
            info("running single web application '{}'".format(opt.runSingleWebsite))
            detection_main(
                opt.runSingleWebsite, payload_list, agent=agent, proxy=proxy,
                verbose=opt.runInVerbose
            )

        elif opt.runMultipleWebsites:
            info("reading from '{}'".format(opt.runMultipleWebsites))
            with open(opt.runMultipleWebsites) as urls:
                for i, url in enumerate(urls, start=1):
                    if PROTOCOL_DETECTION.search(url) is None:
                        url = "http://{}".format(url)
                    url = url.strip()
                    info("currently running on site #{} ('{}')".format(i, url))
                    detection_main(
                        url, payload_list, agent=agent, proxy=proxy,
                        verbose=opt.runInVerbose
                    )
                    print("\n\b")
                    time.sleep(0.5)
    except KeyboardInterrupt:
        fatal("user aborted scanning")
