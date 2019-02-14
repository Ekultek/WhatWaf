import time
try:
    raw_input
except:
    raw_input = input


def set_color(string, level=None):
    """
    set the string color
    """
    color_levels = {
        10: "\033[36m{}\033[0m",
        15: "\033[1m\033[32m{}\033[0m",
        20: "\033[32m{}\033[0m",
        30: "\033[1m\033[33m{}\033[0m",
        35: "\033[33m{}\033[0m",
        40: "\033[1m\033[31m{}\033[0m",
        50: "\033[1m\033[30m{}\033[0m",
        60: "\033[7;31;31m{}\033[0m"
    }
    if level is None:
        return color_levels[20].format(string)
    else:
        return color_levels[int(level)].format(string)


def info(string):
    print(
        "\033[38m[{}]\033[0m".format(time.strftime("%H:%M:%S")) + set_color("[INFO] {}".format(string), level=20)
    )


def debug(string):
    print(
            "\033[38m[{}]\033[0m".format(time.strftime("%H:%M:%S")) + set_color("[DEBUG] {}".format(string), level=10)
    )


def warn(string, minor=False):
    if not minor:
        print(
                "\033[38m[{}]\033[0m".format(time.strftime("%H:%M:%S")) + set_color("[WARN] {}".format(string), level=30)
        )
    else:
        print(
                "\033[38m[{}]\033[0m".format(time.strftime("%H:%M:%S")) + set_color("[WARN] {}".format(string), level=35)
        )


def error(string):
    print(
            "\033[38m[{}]\033[0m".format(time.strftime("%H:%M:%S")) + set_color("[ERROR] {}".format(string), level=40)
    )


def fatal(string):
    print(
            "\033[38m[{}]\033[0m".format(time.strftime("%H:%M:%S")) + set_color("[FATAL] {}".format(string), level=60)
    )


def payload(string):
    print(
        set_color("[PAYLOAD] {}".format(string), level=50)
    )


def success(string):
    print(
            "\033[38m[{}]\033[0m".format(time.strftime("%H:%M:%S")) + set_color("[SUCCESS] {}".format(string), level=15)
    )


def prompt(string, opts, default="n"):
    opts = list(opts)
    choice = raw_input("\033[38m[{}]\033[0m[PROMPT] {}[{}]: ".format(
        time.strftime("%H:%M:%S"), string, "/".join(opts)
    ))
    if choice not in [o.lower() for o in opts]:
        choice = default
    return choice
