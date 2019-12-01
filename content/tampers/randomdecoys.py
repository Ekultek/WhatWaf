import re
import random


__example_payload__ = "<script>alert(1);</script>"
__type__ = "add decoy tags to the script"


def tamper(payload, **kwargs):
    retval = ""
    # https://stackoverflow.com/questions/27044221/regular-expression-to-match-different-script-tags-in-python
    searcher = re.compile(r"(<\s*?script[\s\S]*?(?:(?:src=[\'\"](.*?)[\'\"])(?:[\S\s]*?))?>)([\s\S]*?)(</script>)", re.I)
    if searcher.search(payload) is None:
        # we'll just skip payloads that aren't xss
        return payload
    decoys = (
        "<decoy>", "<lillypopper>",
        "<whatwaf>", "<xanxss>",
        "<teapot.txt>", "<svg>"
    )
    retval += random.choice(decoys)
    for char in payload:
        do_it = random.randint(1, 5) < 3
        if char == "<":
            if do_it:
                retval += "{}{}".format(random.choice(decoys), char)
            else:
                retval += char
        elif char == ">":
            if do_it:
                retval += "{}{}".format(char, random.choice(decoys))
            else:
                retval += char
        else:
            retval += char
    if not retval == payload:
        return retval
    else:
        return tamper(payload, **kwargs)
