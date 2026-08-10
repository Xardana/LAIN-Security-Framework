"""
system_profile.py turns the messy raw text we collected from the target
machine into a clean, tidy dictionary. Different operating systems print
their info in completely different formats, so we isolate all of that messy
text-handling here, and everything downstream (the prompts, the report) just
gets one neat, consistent dict to work with.
Security note: this file only ever reads harmless facts - never passwords,
keys, or cookies.
"""

import re        # [REQUIREMENT: Module] used to pull specific values out of blocks of text.


def _first_line(text):
    """Many commands print one useful line plus a bunch of extra noise; this
    just returns the first line that actually has something in it. It's a
    tiny helper we reuse throughout this file."""
    for line in (text or "").splitlines():      # treat missing text as empty, so this never crashes
        line = line.strip()                    # trim extra spaces off both ends
        if line:                               # skip blank lines
            return line
    return ""                                  # nothing useful was found


def detect_platform(raw_data):
    """This is the one place we decide whether the target is Linux or
    Windows, so that decision can never disagree between different parts of
    the program."""
    tag = str(raw_data.get("platform", "")).lower()   # [REQUIREMENT: Casting]
    if "win" in tag:                                  # does the tag mention Windows?
        return "windows"
    if tag in ("unix", "linux", "darwin"):            # any of the Unix-like names?
        return "linux"

    # If we still don't know, fall back to scanning the OS name itself.
    haystack = f"{raw_data.get('os', '')} {raw_data.get('os_release', '')}".lower()
    return "windows" if "windows" in haystack else "linux"


def _parse_os_release(raw_data, platform):
    """Get a human-friendly OS name. On Linux it's usually tucked inside a
    PRETTY_NAME field; on other platforms we just take the first line."""
    if platform == "linux":
        # Look for something like PRETTY_NAME="Ubuntu 22.04" and pull out just the name part.
        match = re.search(r'PRETTY_NAME="?([^"\n]+)"?', raw_data.get("os_release", ""))
        if match:                                  # did we find it?
            return match.group(1).strip()
    return _first_line(raw_data.get("os_release", ""))


def _parse_cpu(raw_data, platform):
    """Pull a readable CPU model name out of very different command outputs
    depending on the platform."""
    text = raw_data.get("cpu", "")
    if platform == "linux":
        match = re.search(r"Model name:\s*(.+)", text)
        # Use what we found, or just fall back to the first line if nothing matched.
        return match.group(1).strip() if match else _first_line(text)
    match = re.search(r"Name=(.+)", text)               # Windows prints "Name=<cpu>"
    return match.group(1).strip() if match else _first_line(text)


def _parse_tools(raw_data):
    """The raw output is a list of full file paths; we just want the plain
    tool names, with no duplicates."""
    tools = []                                          # the list we build up
    for line in (raw_data.get("tools", "")).splitlines():
        # Take just the filename part of the path, whether it uses "/" or "\".
        name = line.strip().replace("\\", "/").rsplit("/", 1)[-1]
        # Lowercase it and drop a trailing ".exe" if it has one.
        name = name.lower().removesuffix(".exe")
        if name and name not in tools:                  # skip blanks and anything we've already added
            tools.append(name)
    return tools


def _parse_privilege(raw_data, platform):
    """Summarize how much access the current user has, based on `whoami`."""
    user = _first_line(raw_data.get("whoami", "")).lower()
    if not user:                                   # the command gave us nothing back
        return "unknown"
    if platform == "linux":
        """On Linux, "root" is the fully privileged account. We check for an exact
        match rather than "ends with root", because plenty of ordinary accounts are
        named things like chroot, nonroot or notroot, and those were all being
        reported as fully privileged."""
        return "root" if user == "root" else "non-root"
    # On Windows, the username alone doesn't tell us if they're an admin, so just report the name.
    return user


def _kb_to_gib(text):
    """Windows reports memory in kilobytes, which is not much use to a human.
    This turns it into gigabytes, and gives back an empty string if the value
    wasn't a number we could work with."""
    try:
        # [REQUIREMENT: Casting] text -> whole number -> a rounded, readable string.
        return f"{int(text) / (1024 * 1024):.1f}Gi"
    except (TypeError, ValueError):
        return ""


def _parse_memory(raw_data, platform):
    """Pull the actual memory numbers out of the command output.

    This used to just take the first line, which on Linux is the column headings
    ("total used free shared buff/cache available") rather than any real numbers,
    so every report showed those words where the RAM should have been."""
    text = raw_data.get("memory", "")

    if platform == "linux":
        """We match the numbers to the column *headings* instead of counting
        positions along the line. That sounds fussy, but counting positions is
        exactly how this goes wrong: older versions of `free` print
        "total used free shared buffers cached", while newer ones print
        "total used free shared buff/cache available". Position 6 is the cached
        amount on one and the available amount on the other, so anything that
        assumes a fixed position silently reports the wrong number on half the
        machines it ever runs on - and looks perfectly fine doing it."""
        headings = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.lower().startswith("mem:"):
                headings = stripped.split()        # remember the most recent heading row
                continue
            # Drop the "Mem:" label, then pair each number with its own heading.
            numbers = stripped.split()[1:]
            columns = dict(zip(headings, numbers))
            total = columns.get("total", "")
            available = columns.get("available", "")   # simply absent on older versions
            if total and available:
                return f"{total} total, {available} available"
            return total
        return ""                                  # no "Mem:" line found at all

    """Windows prints this as "Name=value" lines instead, so we read them into a
    small lookup and then convert the numbers into something readable."""
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:                              # only keep real "key=value" lines
            values[key.strip()] = value.strip()
    total = _kb_to_gib(values.get("TotalVisibleMemorySize"))
    free = _kb_to_gib(values.get("FreePhysicalMemory"))
    if total and free:
        return f"{total} total, {free} free"
    return total or free                           # whichever one we managed to read


def _parse_network(raw_data, platform):
    """Collect only the network interface names (like eth0 or Wi-Fi) -
    deliberately not IP addresses - so the profile stays free of sensitive
    details."""
    text = raw_data.get("network", "")
    interfaces = []
    if platform == "linux":
        # Matches lines like "2: eth0:" and pulls out just the interface name.
        names = re.findall(r"^\d+:\s*([^:@\s]+)", text, re.MULTILINE)
        names += re.findall(r"^(\w+):\s+flags=", text, re.MULTILINE)  # fallback format some tools use
    else:
        # Matches lines like "Ethernet adapter Wi-Fi:" and pulls out the adapter name.
        names = [m.strip() for m in re.findall(r"adapter\s+(.+?):", text)]
    for name in names:
        if name and name not in interfaces:             # keep the order, but skip duplicates
            interfaces.append(name)
    return interfaces


def _parse_packages(raw_data):
    """Turn the output of `pip list` into "name==version" strings, skipping
    the header row, the separator line, and anything that isn't really a package."""
    packages = []
    for line in (raw_data.get("packages", "")).splitlines():
        parts = line.split()                            # split on any whitespace
        # A real package row looks like "<name> <version>", and the version starts with a digit.
        if len(parts) >= 2 and re.match(r"\d", parts[1]):
            packages.append(f"{parts[0]}=={parts[1]}")  # e.g. "numpy==1.26.0"
    return packages


def parse(raw_data):
    """The one function everything else calls. It runs all the helpers above
    and returns a single, clean dict that both prompt_builder and
    report_writer can use."""
    raw_data = raw_data or {}                           # treat missing data as an empty dict
    platform = detect_platform(raw_data)                # figure this out once, and reuse it below

    # Each value below comes from one of the small helper functions above, so this
    # reads like a table of contents for everything we know about the target.
    return {
        "platform": platform,
        "os": _first_line(raw_data.get("os", "")) or "unknown",
        "os_release": _parse_os_release(raw_data, platform),
        "arch": _first_line(raw_data.get("arch", "")) or "unknown",
        "python_version": _first_line(raw_data.get("python_version", "")),
        "privilege": _parse_privilege(raw_data, platform),
        "cpu": _parse_cpu(raw_data, platform),
        "memory": _parse_memory(raw_data, platform),
        "tools": _parse_tools(raw_data),
        "network": _parse_network(raw_data, platform),
        "packages": _parse_packages(raw_data),
    }
