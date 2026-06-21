"""
system_profile.py
=================
Single responsibility: take the raw command output collected by
target_connector.py and turn it into a clean, structured profile dictionary
that is safe to hand to the AI model.

It must never request or parse secrets (passwords, tokens, SSH/API keys,
cookies, browser history). target_connector only runs read-only, non-sensitive
enumeration, and this module keeps it that way.

The most important output field is "platform" ("linux" or "windows"): the
prompt_builder uses it to choose which OS-specific guidance to send, so the
prompts always match the target that was actually detected.

Coding requirements demonstrated in THIS file:
    * Functions - each piece of parsing is its own small def.
    * Modules   - standard-library `re` for pattern matching in raw text.
    * Casting   - values are coerced to str with str(...) before slicing/parsing
                  so the code is safe even if a field arrives as another type.
"""

import re        # standard library: regular-expression parsing of command output


def _first_line(text):
    """Return the first non-blank line of a block of text (or "" if none)."""
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def detect_platform(raw_data):
    """Decide whether the target is 'linux' or 'windows'.

    target_connector tags its output as 'unix'/'windows'; here we normalize
    'unix' to 'linux' and cross-check the OS banners, so the decision is made
    once, authoritatively, instead of being guessed later in prompt_builder.
    """
    # [REQUIREMENT: Casting] force the tag to a str before calling .lower(),
    # in case it is missing (None) or some non-string value.
    tag = str(raw_data.get("platform", "")).lower()
    if "win" in tag:
        return "windows"
    if tag in ("unix", "linux", "darwin"):
        return "linux"

    # Fall back to the OS banners if the tag is missing or unrecognised.
    haystack = f"{raw_data.get('os', '')} {raw_data.get('os_release', '')}".lower()
    return "windows" if "windows" in haystack else "linux"


def _parse_os_release(raw_data, platform):
    """Pull a friendly OS name out of the release info for each platform."""
    if platform == "linux":
        match = re.search(r'PRETTY_NAME="?([^"\n]+)"?', raw_data.get("os_release", ""))
        if match:
            return match.group(1).strip()
    return _first_line(raw_data.get("os_release", ""))


def _parse_cpu(raw_data, platform):
    """Extract a readable CPU model name from lscpu / wmic output."""
    text = raw_data.get("cpu", "")
    if platform == "linux":
        match = re.search(r"Model name:\s*(.+)", text)
        return match.group(1).strip() if match else _first_line(text)
    match = re.search(r"Name=(.+)", text)
    return match.group(1).strip() if match else _first_line(text)


def _parse_tools(raw_data):
    """Turn the raw `command -v` / `where` output (a list of paths) into a
    deduplicated list of available tool names (e.g. ['python3', 'bash'])."""
    tools = []
    for line in (raw_data.get("tools", "")).splitlines():
        # Keep only the final path component, then drop a trailing .exe.
        name = line.strip().replace("\\", "/").rsplit("/", 1)[-1]
        name = name.lower().removesuffix(".exe")
        if name and name not in tools:
            tools.append(name)
    return tools


def _parse_privilege(raw_data, platform):
    """Summarise the current user's permission level from `whoami`."""
    # [REQUIREMENT: Casting] str(...) (inside _first_line) keeps this safe even
    # if whoami output is missing; .lower() then normalises the account name.
    user = _first_line(raw_data.get("whoami", "")).lower()
    if platform == "linux":
        return "root" if user.endswith("root") else "non-root"
    # On Windows, whoami alone cannot confirm elevation, so just report the account.
    return user or "unknown"


def _parse_network(raw_data, platform):
    """Extract the list of network interface NAMES only (no addresses/secrets)."""
    text = raw_data.get("network", "")
    interfaces = []
    if platform == "linux":
        # `ip addr`: "2: eth0: <...>"; fall back to ifconfig's "eth0: flags=".
        names = re.findall(r"^\d+:\s*([^:@\s]+)", text, re.MULTILINE)
        names += re.findall(r"^(\w+):\s+flags=", text, re.MULTILINE)
    else:
        # ipconfig /all: "Ethernet adapter Ethernet:" / "Wireless LAN adapter Wi-Fi:"
        names = [m.strip() for m in re.findall(r"adapter\s+(.+?):", text)]
    for name in names:
        if name and name not in interfaces:
            interfaces.append(name)
    return interfaces


def _parse_packages(raw_data):
    """Parse `pip list` output into a list of 'name==version' strings, skipping
    the header row, the separator row, and any pip warning/notice lines."""
    packages = []
    for line in (raw_data.get("packages", "")).splitlines():
        parts = line.split()
        # A real row is "<name> <version>" where the version starts with a digit.
        if len(parts) >= 2 and re.match(r"\d", parts[1]):
            packages.append(f"{parts[0]}=={parts[1]}")
    return packages


def parse(raw_data):
    """Public entry point: build the structured profile dict from raw output.

    This is the function main.py calls. It runs the small helpers above and
    returns one dictionary that prompt_builder and report_writer both rely on.
    """
    raw_data = raw_data or {}
    platform = detect_platform(raw_data)

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
