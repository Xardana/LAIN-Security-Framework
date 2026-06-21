# system_profile.py - turns the messy raw command output from target_connector into a
# clean, structured dictionary. Architectural role: this is the "parsing/normalisation"
# layer. The raw text differs wildly between OSes; everything downstream (prompts, report)
# wants one tidy dict, so we isolate all the fragile text-wrangling here.
# Security note: it only ever reads non-sensitive facts - never passwords/keys/cookies.

import re        # [REQUIREMENT: Module] regular-expression engine for extracting values from text.


def _first_line(text):
    # WHY (logic): many commands print one useful line plus noise; this returns the first
    # line that actually has content. A tiny helper reused all over this file (DRY principle).
    # HOW (syntax): `text or ""` guards against text being None - None is "falsy", so the
    # expression evaluates to "" and .splitlines() won't crash. str.splitlines() splits the
    # string on line boundaries (\n, \r\n, ...) and returns a LIST of lines (no newline chars).
    for line in (text or "").splitlines():
        line = line.strip()                    # str.strip() returns a new string with edge whitespace removed
        if line:                               # a non-empty string is truthy; this skips blank lines
            return line                        # early return on the first real line
    return ""                                  # loop finished with nothing found


def detect_platform(raw_data):
    # WHY (logic): the single source of truth for "is this Linux or Windows." We decide it
    # ONCE and reuse it, so the OS classification can never disagree between functions.
    # HOW (syntax): str(...) is an explicit CAST [REQUIREMENT: Casting] - it converts whatever
    # raw_data.get returns into a string so .lower() is safe even if the key is missing (None)
    # or some non-string type. dict.get("platform", "") returns "" when the key is absent.
    tag = str(raw_data.get("platform", "")).lower()   # .lower() returns a new lower-cased string
    if "win" in tag:                                  # `in` on a string tests SUBSTRING membership
        return "windows"
    if tag in ("unix", "linux", "darwin"):            # `in` on a tuple tests EQUALITY to any element
        return "linux"

    # Fallback if the tag was missing/unknown: scan the OS banners themselves.
    # f-string builds one combined string; .lower() normalises case for the substring test.
    haystack = f"{raw_data.get('os', '')} {raw_data.get('os_release', '')}".lower()
    return "windows" if "windows" in haystack else "linux"


def _parse_os_release(raw_data, platform):
    # WHY (logic): produce a human-friendly OS name. Linux hides it in a PRETTY_NAME field;
    # Windows/other cases just take the first line.
    if platform == "linux":
        # re.search(pattern, string) scans for the FIRST match anywhere and returns a Match
        # object (or None). Pattern: PRETTY_NAME="..." where "?" makes the quote optional and
        # ([^"\n]+) is a CAPTURE GROUP meaning "one or more characters that are NOT a quote or newline".
        match = re.search(r'PRETTY_NAME="?([^"\n]+)"?', raw_data.get("os_release", ""))
        if match:                                  # truthy only if something matched
            return match.group(1).strip()          # .group(1) = the text captured by the first (...)
    return _first_line(raw_data.get("os_release", ""))


def _parse_cpu(raw_data, platform):
    # WHY (logic): pull a readable CPU model from very different command outputs.
    text = raw_data.get("cpu", "")
    if platform == "linux":
        # \s* = zero-or-more whitespace; (.+) captures "one or more of any char" to end of line.
        match = re.search(r"Model name:\s*(.+)", text)
        # Ternary: use the captured group if matched, else fall back to the first line.
        return match.group(1).strip() if match else _first_line(text)
    match = re.search(r"Name=(.+)", text)               # Windows wmic prints "Name=<cpu>"
    return match.group(1).strip() if match else _first_line(text)


def _parse_tools(raw_data):
    # WHY (logic): the raw output is a list of full executable paths; we want just the tool
    # NAMES, de-duplicated. This shows several core string operations chained together.
    tools = []                                          # accumulator list we append to
    for line in (raw_data.get("tools", "")).splitlines():
        # Build the basename by hand:
        #   .replace("\\", "/")  -> normalise Windows backslashes to forward slashes
        #   .rsplit("/", 1)      -> split from the RIGHT on "/", at most 1 time -> ["dir", "name"]
        #   [-1]                 -> last element (negative indexing counts from the end)
        name = line.strip().replace("\\", "/").rsplit("/", 1)[-1]
        # .lower() normalises case; .removesuffix(".exe") strips a trailing ".exe" if present
        # (added in Python 3.9; returns the string unchanged if the suffix isn't there).
        name = name.lower().removesuffix(".exe")
        if name and name not in tools:                  # skip blanks AND duplicates (`not in` = membership test)
            tools.append(name)                          # list.append adds one item to the end
    return tools


def _parse_privilege(raw_data, platform):
    # WHY (logic): summarise the user's permission level from `whoami`.
    # _first_line uses str() internally; .lower() normalises the account name.
    user = _first_line(raw_data.get("whoami", "")).lower()
    if platform == "linux":
        # str.endswith(suffix) returns True/False. On Linux, root is the privileged account.
        return "root" if user.endswith("root") else "non-root"
    # On Windows, whoami alone can't prove admin rights, so we just report the account name.
    # `user or "unknown"` yields "unknown" when user is an empty string.
    return user or "unknown"


def _parse_network(raw_data, platform):
    # WHY (logic): collect ONLY interface names (eth0, Wi-Fi) - deliberately not IPs - so the
    # profile stays non-sensitive. Demonstrates re.findall, which returns EVERY match.
    text = raw_data.get("network", "")
    interfaces = []
    if platform == "linux":
        # re.findall returns a LIST of all matches (just the captured group when one (...) exists).
        # r"^\d+:\s*([^:@\s]+)" with re.MULTILINE: ^ matches the start of EACH line (not just the
        # whole string); \d+ = one-or-more digits; then capture the name (chars that aren't :@/space).
        names = re.findall(r"^\d+:\s*([^:@\s]+)", text, re.MULTILINE)   # matches "2: eth0:"
        # `+=` on a list EXTENDS it with the items of the right-hand list (ifconfig-style fallback).
        names += re.findall(r"^(\w+):\s+flags=", text, re.MULTILINE)
    else:
        # LIST COMPREHENSION: "[expression for item in iterable]" builds a new list in one line.
        # Here it strips whitespace from each adapter name found by findall.
        names = [m.strip() for m in re.findall(r"adapter\s+(.+?):", text)]  # "Ethernet adapter X:"
    for name in names:
        if name and name not in interfaces:             # dedupe while PRESERVING order
            interfaces.append(name)
    return interfaces


def _parse_packages(raw_data):
    # WHY (logic): turn `pip list` output into "name==version" strings, skipping the header,
    # the dashed separator, and any pip warning/notice lines (which aren't packages).
    packages = []
    for line in (raw_data.get("packages", "")).splitlines():
        parts = line.split()                            # str.split() with no arg splits on ANY whitespace
        # A genuine package row is "<name> <version>" AND the version starts with a digit.
        # re.match anchors at the START of the string (parts[1]); we just need the first char to be \d.
        # `len(parts) >= 2 and ...` short-circuits: if there's only one token, the regex isn't even checked.
        if len(parts) >= 2 and re.match(r"\d", parts[1]):
            packages.append(f"{parts[0]}=={parts[1]}")  # e.g. "numpy==1.26.0"
    return packages


def parse(raw_data):
    # WHY (logic): the ONLY public function (main.py calls this). It orchestrates the helpers
    # above and returns a single dict that prompt_builder and report_writer both consume.
    # Returning a plain dict (vs a custom class) keeps the data trivially serialisable to JSON.
    raw_data = raw_data or {}                           # guard: if None, use an empty dict
    platform = detect_platform(raw_data)                # compute once, pass into the helpers

    # A dict literal. Each value is produced by a focused helper, so this function reads like
    # a table of contents for the profile.
    return {
        "platform": platform,
        "os": _first_line(raw_data.get("os", "")) or "unknown",
        "os_release": _parse_os_release(raw_data, platform),
        "arch": _first_line(raw_data.get("arch", "")) or "unknown",
        "python_version": _first_line(raw_data.get("python_version", "")),
        "privilege": _parse_privilege(raw_data, platform),
        "cpu": _parse_cpu(raw_data, platform),
        "memory": _first_line(raw_data.get("memory", "")),
        "tools": _parse_tools(raw_data),
        "network": _parse_network(raw_data, platform),
        "packages": _parse_packages(raw_data),
    }
