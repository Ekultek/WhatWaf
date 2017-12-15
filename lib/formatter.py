def set_color(string, level=None):
    """
    set the string color
    """
    color_levels = {
        10: "\033[36m{}\033[0m",
        15: "\033[1m\033[32m{}\033[0m",
        20: "\033[32m{}\033[0m",
        30: "\033[1m\033[33m{}\033[0m",
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
        set_color("[INFO] {}".format(string), level=20)
    )


def debug(string):
    print(
        set_color("[DEBUG] {}".format(string), level=10)
    )


def warn(string):
    print(
        set_color("[WARN] {}".format(string), level=30)
    )


def error(string):
    print(
        set_color("[ERROR] {}".format(string), level=40)
    )


def fatal(string):
    print(
        set_color("[FATAL] {}".format(string), level=60)
    )


def payload(string):
    print(
        set_color("[PAYLOAD] {}".format(string), level=50)
    )


def success(string):
    print(
        set_color("[SUCCESS] {}".format(string), level=15)
    )