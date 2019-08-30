import re


__example_payload__ = "<script>alert(1);</script>"
__type__ = "add decoy tags to the script"


def tamper(payload, **kwargs):
    # 
    searcher = re.compile(r"(<\s*?script[\s\S]*?(?:(?:src=[\'\"](.*?)[\'\"])(?:[\S\s]*?))?>)([\s\S]*?)(</script>)", re.I)
