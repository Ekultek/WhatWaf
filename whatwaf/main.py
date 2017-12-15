import sys
import shlex
import time
import subprocess

from lib.cmd import WhatWafParser
from content import detection_main
from lib.settings import (
    configure_request_headers,
    WAF_REQUEST_DETECTION_PAYLOADS,
    BANNER
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
            info("running single web application '{}'".format(opt.runSingleWebsite))
            detection_main(
                opt.runSingleWebsite, payload_list, agent=agent, proxy=proxy,
                verbose=opt.runInVerbose
            )

        elif opt.runMultipleWebsites:
            info("reading from '{}'".format(opt.runMultipleWebsites))
            with open(opt.runMultipleWebsites) as urls:
                for i, url in enumerate(urls, start=1):
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
