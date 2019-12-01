from setuptools import setup, find_packages

from lib.settings import VERSION
from lib.formatter import fatal, error
from lib.firewall_found import request_issue_creation


try:
    setup(
        name='whatwaf',
        version=VERSION,
        packages=find_packages(),
        url='https://github.com/ekultek/whatwaf',
        license='GPLv3',
        author='ekultek',
        author_email='god_lok1@protonmail.com',
        description='Detect and bypass web application firewalls and protection systems',
        scripts=["whatwaf"],
        install_requires=open("requirements.txt").read().split("\n")
    )
except Exception as e:
    import sys, traceback

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
