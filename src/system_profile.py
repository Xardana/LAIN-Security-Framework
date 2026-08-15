"""
This file takes the messy raw text we pulled off the target machine and turns it
into one clean dictionary. Every operating system prints its info differently, so
we keep all that messy text-wrangling in here, and everything downstream just gets
one tidy, consistent result to work with.

One security note: this file only ever reads harmless facts. Never passwords, keys,
or cookies.
"""

import re        # [REQUIREMENT: Module] used to pick specific values out of blocks of text.


def _first_line(text):
    """Lots of commands print one useful line and a pile of noise. This just grabs
    the first line that actually has something on it. Tiny helper, used all over
    this file."""
    for line in (text or "").splitlines():      # missing text counts as empty, so this never crashes
        line = line.strip()                    # trim spaces off both ends
        if line:                               # skip blank lines
            return line
    return ""                                  # found nothing useful


def detect_platform(raw_data):
    """The one place we decide Linux or Windows, so that call can never disagree
    with itself elsewhere in the program."""
    tag = str(raw_data.get("platform", "")).lower()   # [REQUIREMENT: Casting]
    if "win" in tag:                                  # tag mentions Windows?
        return "windows"
    if tag in ("unix", "linux", "darwin"):            # one of the Unix-ish names?
        return "linux"

    # Still not sure? Fall back to scanning the OS name itself.
    haystack = f"{raw_data.get('os', '')} {raw_data.get('os_release', '')}".lower()
    return "windows" if "windows" in haystack else "linux"


def _parse_os_release(raw_data, platform):
    """Get a readable OS name. On Linux it's usually hiding in a PRETTY_NAME field.
    Anywhere else, just take the first line."""
    if platform == "linux":
        # Find something like PRETTY_NAME="Ubuntu 22.04" and pull out just the name.
        match = re.search(r'PRETTY_NAME="?([^"\n]+)"?', raw_data.get("os_release", ""))
        if match:
            return match.group(1).strip()
    return _first_line(raw_data.get("os_release", ""))


def _parse_cpu(raw_data, platform):
    """Pull a readable CPU name out of output that looks totally different on each OS."""
    text = raw_data.get("cpu", "")
    if platform == "linux":
        match = re.search(r"Model name:\s*(.+)", text)
        # Use what we found, or just fall back to the first line.
        return match.group(1).strip() if match else _first_line(text)
    match = re.search(r"Name=(.+)", text)               # Windows prints "Name=<cpu>"
    return match.group(1).strip() if match else _first_line(text)


def _parse_tools(raw_data):
    """The raw output is a list of full file paths. We just want the plain tool
    names, no duplicates."""
    tools = []
    for line in (raw_data.get("tools", "")).splitlines():
        # Take just the filename at the end of the path, works with "/" or "\".
        name = line.strip().replace("\\", "/").rsplit("/", 1)[-1]
        # Lowercase it and drop a trailing ".exe" if there is one.
        name = name.lower().removesuffix(".exe")
        if name and name not in tools:                  # skip blanks and repeats
            tools.append(name)
    return tools


def _parse_privilege(raw_data, platform):
    """Sum up how much access the current user has, from `whoami`."""
    user = _first_line(raw_data.get("whoami", "")).lower()
    if not user:                                   # command told us nothing
        return "unknown"
    if platform == "linux":
        # On Linux, "root" is the all-powerful account. We check for an exact match,
        # not "ends with root", because plenty of normal accounts are called things
        # like chroot, nonroot or notroot, and those were all getting reported as root.
        return "root" if user == "root" else "non-root"
    # On Windows the username alone doesn't tell us if they're an admin, so just report it.
    return user


def _kb_to_gib(text):
    """Windows gives memory in kilobytes, which means nothing to a human. Turn it
    into gigabytes, or an empty string if it wasn't a number we could use."""
    try:
        # [REQUIREMENT: Casting] text -> whole number -> a short readable string.
        return f"{int(text) / (1024 * 1024):.1f}Gi"
    except (TypeError, ValueError):
        return ""


def _parse_memory(raw_data, platform):
    """Pull the real memory numbers out of the output.

    This used to just take the first line, which on Linux is the column headings
    ("total used free shared buff/cache available"), not any actual numbers. So every
    report showed those words where the RAM should have been."""
    text = raw_data.get("memory", "")

    if platform == "linux":
        # We match each number to its column heading instead of counting positions
        # along the line. Sounds fussy, but counting positions is exactly how this
        # breaks: older `free` prints "total used free shared buffers cached", newer
        # prints "total used free shared buff/cache available". Column 6 is "cached" on
        # one and "available" on the other, so anything that assumes a fixed position
        # quietly reports the wrong number on half the machines and looks fine doing it.
        headings = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.lower().startswith("mem:"):
                headings = stripped.split()        # remember the latest heading row
                continue
            # Drop the "Mem:" label, then pair each number with its heading.
            numbers = stripped.split()[1:]
            columns = dict(zip(headings, numbers))
            total = columns.get("total", "")
            available = columns.get("available", "")   # just missing on older versions
            if total and available:
                return f"{total} total, {available} available"
            return total
        return ""                                  # never found a "Mem:" line

    # Windows prints "Name=value" lines instead, so read those into a lookup and
    # convert the numbers to something readable.
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
    """Grab only the network interface names (like eth0 or Wi-Fi), on purpose not the
    IP addresses, so the profile stays clear of anything sensitive."""
    text = raw_data.get("network", "")
    interfaces = []
    if platform == "linux":
        # Matches lines like "2: eth0:" and pulls out the name.
        names = re.findall(r"^\d+:\s*([^:@\s]+)", text, re.MULTILINE)
        names += re.findall(r"^(\w+):\s+flags=", text, re.MULTILINE)  # fallback some tools use
    else:
        # Matches lines like "Ethernet adapter Wi-Fi:" and pulls out the adapter name.
        names = [m.strip() for m in re.findall(r"adapter\s+(.+?):", text)]
    for name in names:
        if name and name not in interfaces:             # keep the order, drop duplicates
            interfaces.append(name)
    return interfaces


def _parse_packages(raw_data):
    """Turn `pip list` output into "name==version" strings, skipping the header, the
    separator line, and anything that isn't really a package."""
    packages = []
    for line in (raw_data.get("packages", "")).splitlines():
        parts = line.split()                            # split on whitespace
        # A real package row is "<name> <version>", and the version starts with a digit.
        if len(parts) >= 2 and re.match(r"\d", parts[1]):
            packages.append(f"{parts[0]}=={parts[1]}")  # e.g. "numpy==1.26.0"
    return packages


def parse(raw_data):
    """The one function everything else calls. Runs all the helpers above and hands
    back a single clean dict that both prompt_builder and report_writer can use."""
    raw_data = raw_data or {}                           # missing data counts as empty
    platform = detect_platform(raw_data)                # work this out once, reuse it below

    # Each value comes from one of the small helpers above, so this reads like a table
    # of contents for everything we know about the target.
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
