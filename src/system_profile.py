# system_profile.py - turns the raw command output from target_connector into a
# clean, structured dict. It only reads non-sensitive info (never passwords/keys).

import re        # [REQUIREMENT: Module] regular expressions for pulling values out of text


def _first_line(text):
    # Return the first non-blank line of a block of text, or "" if there is none.
    # "text or ''" guards against text being None (None is falsy -> use "").
    for line in (text or "").splitlines():     # splitlines() breaks the text into a list of lines
        line = line.strip()                    # remove leading/trailing whitespace
        if line:                               # an empty string is falsy; skip blank lines
            return line                        # return the first line that has content
    return ""                                  # nothing found -> empty string


def detect_platform(raw_data):
    # Decide "linux" or "windows" once, authoritatively.
    # [REQUIREMENT: Casting] str(...) forces the value to a string before .lower(),
    # in case the "platform" key is missing (None) or some other type.
    tag = str(raw_data.get("platform", "")).lower()   # .get(key, "") returns "" if key is absent
    if "win" in tag:                                  # "in" tests substring membership
        return "windows"
    if tag in ("unix", "linux", "darwin"):            # "in" on a tuple tests equality to any item
        return "linux"

    # If the tag was missing/unknown, fall back to scanning the OS banners.
    # f-string joins the two fields; .lower() makes the search case-insensitive.
    haystack = f"{raw_data.get('os', '')} {raw_data.get('os_release', '')}".lower()
    return "windows" if "windows" in haystack else "linux"


def _parse_os_release(raw_data, platform):
    # Pull a friendly OS name out of the release info.
    if platform == "linux":
        # Search for the PRETTY_NAME="..." line and capture what's inside the quotes.
        match = re.search(r'PRETTY_NAME="?([^"\n]+)"?', raw_data.get("os_release", ""))
        if match:                                  # match is None if the pattern wasn't found
            return match.group(1).strip()          # group(1) = the captured text inside (...)
    return _first_line(raw_data.get("os_release", ""))   # Windows / fallback: just the first line


def _parse_cpu(raw_data, platform):
    # Extract a readable CPU model name.
    text = raw_data.get("cpu", "")
    if platform == "linux":
        match = re.search(r"Model name:\s*(.+)", text)   # "Model name:" then capture the rest of the line
        return match.group(1).strip() if match else _first_line(text)
    match = re.search(r"Name=(.+)", text)               # Windows wmic prints "Name=..."
    return match.group(1).strip() if match else _first_line(text)


def _parse_tools(raw_data):
    # Convert the raw list of tool paths into a deduplicated list of tool NAMES.
    tools = []                                          # the result list, built up below
    for line in (raw_data.get("tools", "")).splitlines():
        # Take the last path component: replace Windows "\" with "/", then rsplit
        # on "/" keeping the final piece. e.g. "/usr/bin/python3" -> "python3".
        name = line.strip().replace("\\", "/").rsplit("/", 1)[-1]
        name = name.lower().removesuffix(".exe")        # normalise case, drop a trailing ".exe"
        if name and name not in tools:                  # skip blanks and duplicates
            tools.append(name)                          # add this tool name to the list
    return tools


def _parse_privilege(raw_data, platform):
    # Summarise the current user's permission level from the `whoami` output.
    # [REQUIREMENT: Casting] _first_line uses str() internally; .lower() normalises it.
    user = _first_line(raw_data.get("whoami", "")).lower()
    if platform == "linux":
        # On Linux, the root account is the privileged one.
        return "root" if user.endswith("root") else "non-root"
    # On Windows, whoami alone can't confirm admin rights, so just report the account.
    return user or "unknown"                            # "user or 'unknown'" handles an empty string


def _parse_network(raw_data, platform):
    # Extract only interface NAMES (e.g. eth0, Wi-Fi) - no IP addresses or secrets.
    text = raw_data.get("network", "")
    interfaces = []
    if platform == "linux":
        # re.findall returns EVERY match as a list. "^\d+:\s*([^:@\s]+)" matches
        # lines like "2: eth0:" and captures the name. re.MULTILINE makes "^" match
        # the start of each line, not just the whole string.
        names = re.findall(r"^\d+:\s*([^:@\s]+)", text, re.MULTILINE)
        names += re.findall(r"^(\w+):\s+flags=", text, re.MULTILINE)   # ifconfig style; += extends the list
    else:
        # ipconfig prints "Ethernet adapter Ethernet:" - capture the bit after "adapter".
        names = [m.strip() for m in re.findall(r"adapter\s+(.+?):", text)]  # list comprehension
    for name in names:
        if name and name not in interfaces:             # dedupe while keeping order
            interfaces.append(name)
    return interfaces


def _parse_packages(raw_data):
    # Parse `pip list` output into a list of "name==version" strings.
    packages = []
    for line in (raw_data.get("packages", "")).splitlines():
        parts = line.split()                            # split the line on whitespace into a list
        # A real package row is "<name> <version>" where the version starts with a digit.
        # re.match looks only at the START of parts[1]; this skips the header and
        # any "[notice]"/"WARNING" lines pip sometimes prints.
        if len(parts) >= 2 and re.match(r"\d", parts[1]):
            packages.append(f"{parts[0]}=={parts[1]}")  # e.g. "numpy==1.26.0"
    return packages


def parse(raw_data):
    # Public entry point (called by main.py): build the structured profile dict.
    raw_data = raw_data or {}                           # guard against None -> use empty dict
    platform = detect_platform(raw_data)                # work out the OS once, reuse below

    # Build and return one dict; each value comes from a small helper above.
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
