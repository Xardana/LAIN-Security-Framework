"""Parses the raw enumeration output collected by target_connector.py into a
clean, structured profile that is safe to send to the AI model.

It must never request or parse secrets (passwords, tokens, SSH/API keys,
cookies, browser history); target_connector only ever runs read-only,
non-sensitive enumeration, and this module keeps it that way.

The most important output field is "platform" ("linux" or "windows"): the
prompt_builder uses it to decide which OS-specific audit guidance to send,
so the prompts always match the target that was actually detected.
"""

import re


def _first_line(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def detect_platform(raw_data):
    """Return a normalized 'linux' or 'windows' from the raw enumeration.

    target_connector tags output as 'unix'/'windows'; we normalize 'unix' to
    'linux' and cross-check the OS strings so the decision is authoritative
    rather than a guess made later in prompt_builder.
    """
    tag = str(raw_data.get("platform", "")).lower()
    if "win" in tag:
        return "windows"
    if tag in ("unix", "linux", "darwin"):
        return "linux"

    # Fall back to the OS banners if the tag is missing/unknown.
    haystack = f"{raw_data.get('os', '')} {raw_data.get('os_release', '')}".lower()
    return "windows" if "windows" in haystack else "linux"


def _parse_os_release(raw_data, platform):
    if platform == "linux":
        match = re.search(r'PRETTY_NAME="?([^"\n]+)"?', raw_data.get("os_release", ""))
        if match:
            return match.group(1).strip()
    return _first_line(raw_data.get("os_release", ""))


def _parse_cpu(raw_data, platform):
    text = raw_data.get("cpu", "")
    if platform == "linux":
        match = re.search(r"Model name:\s*(.+)", text)
        return match.group(1).strip() if match else _first_line(text)
    match = re.search(r"Name=(.+)", text)
    return match.group(1).strip() if match else _first_line(text)


def _parse_tools(raw_data):
    """Turn the raw `command -v` / `where` output (a list of paths) into a
    deduplicated list of available tool names."""
    tools = []
    for line in (raw_data.get("tools", "")).splitlines():
        name = line.strip().replace("\\", "/").rsplit("/", 1)[-1]
        name = name.lower().removesuffix(".exe")
        if name and name not in tools:
            tools.append(name)
    return tools


def _parse_privilege(raw_data, platform):
    user = _first_line(raw_data.get("whoami", "")).lower()
    if platform == "linux":
        return "root" if user.endswith("root") else "non-root"
    # On Windows whoami alone can't confirm elevation; report the account.
    return user or "unknown"


def parse(raw_data):
    """Build the structured profile dict consumed by prompt_builder/main."""
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
    }
