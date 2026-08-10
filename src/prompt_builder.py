"""
prompt_builder.py writes out the instructions we send to the AI. It doesn't
talk to the network (ai_client.py does that) and it doesn't run any scripts -
it only builds text. Keeping the wording separate from everything else makes
it easy to tweak what we tell the AI without touching any other code. We keep
the wording short on purpose, since the AI model we're using is a small one.
"""

"""The instructions we send the AI are built from a few fixed blocks of text,
joined together each time. Writing them once at the top of the file means the
exact same wording is used every time, so the AI behaves consistently, and we
never have to retype it. Wrapping the text in parentheses across several lines
just lets us write one long block of text without needing a "+" on every line."""

ROLE = (
    "You are a defensive security auditor working on an explicitly authorized, "
    "read-only audit. You write small READ-ONLY Python scripts that inspect a "
    "single authorized machine and report findings. You only audit; you never "
    "change the system and you never produce exploit code."
)

# The "\n" bits are line breaks, so this prints as a neat bullet list for the AI to read.
SAFETY_RULES = (
    "Hard rules, never break them:\n"
    "- READ-ONLY only. Never write, move, delete, or modify any file or setting.\n"
    "- No exploitation or exploit code, and no destructive actions of any kind.\n"
    "- No privilege escalation, no sudo/runas, no credential, token, key, or cookie reading.\n"
    "- No persistence, no new users, and no stealth or evasion techniques.\n"
    "- No unauthorized network scanning and no connections to other hosts.\n"
    "- No disabling of security tools. No eval/exec of downloaded code.\n"
    "- If a check would require any of the above, skip it and note why instead."
)

"""We ask the AI's generated script to always print its results in this exact
shape, so that report_writer can read every task's results the same way,
instead of having to guess at whatever format the AI feels like using."""
FINDINGS_SCHEMA = (
    "{\n"
    '  "task": "<this task name>",\n'
    '  "findings": [\n'
    '    {"title": "<short title>",\n'
    '     "severity": "info|low|medium|high|critical",\n'
    '     "detail": "<what was found, one or two sentences>",\n'
    '     "evidence": "<the raw value or command output it is based on>",\n'
    '     "cves": ["CVE-0000-0000"]}\n'
    "  ]\n"
    "}\n"
    "Rules for this output: use an empty findings list when nothing notable is "
    "found; severity must be exactly one of the listed words; include cves only "
    "when a specific CVE applies, otherwise use an empty list."
)

# This glues the schema above onto the end of the instructions below it.
OUTPUT_CONTRACT = (
    "Reply with ONLY a JSON object, no prose, in this exact shape:\n"
    '{"script": "<python3 source>", "explanation": "<one sentence>"}\n'
    # Models habitually present code in markdown fences, and they do it inside the
    # JSON string too, which leaves us with something that isn't valid Python. We
    # strip those off in ai_client anyway, but asking here saves a wasted round-trip.
    "The \"script\" value must be raw Python source starting at the first line of "
    "code. Do NOT wrap it in markdown code fences or backticks.\n"
    "The script must run under python3, use only the standard library, and wrap "
    "every check in try/except so one failure never stops the rest. The script "
    "must print EXACTLY ONE JSON object to stdout and nothing else, in this "
    "shape:\n" + FINDINGS_SCHEMA
)

# --- Per-OS guidance. We attach exactly one of these depending on the detected platform. ---
LINUX_HINTS = (
    "Target is Linux. Prefer reading /etc, /proc and standard files, or running "
    "read-only commands (uname, id, ss, systemctl is-enabled, sysctl) via "
    "subprocess with a timeout. Do not assume root."
)

WINDOWS_HINTS = (
    "Target is Windows. Prefer read-only PowerShell/CIM queries (Get-CimInstance, "
    "Get-LocalUser, Get-NetTCPConnection, Get-MpComputerStatus) or 'reg query' "
    "run via subprocess with a timeout. Do not assume Administrator."
)

"""--- The list of audit tasks. Each task name points to a small dict holding
what to ask for, plus a Linux hint and a Windows hint. Keeping all of this data
in one place means we can add or remove a task just by editing this list,
without touching any of the code below. ---"""
AUDIT_TASKS = {
    "patch_status": {
        "ask": "Check the OS patch / update status and report pending security updates.",
        "linux": "Use the available package manager read-only (apt list --upgradable, dnf check-update, or rpm -qa) without installing anything.",
        "windows": "Query installed hotfixes via Get-HotFix and the last update time; do not trigger any update.",
    },
    "listening_ports": {
        "ask": "List listening network ports and the owning process for each.",
        "linux": "Parse `ss -tulpn` or read /proc/net/tcp; do not open any socket yourself.",
        "windows": "Use Get-NetTCPConnection where State is Listen, joined to the owning process name.",
    },
    "local_accounts": {
        "ask": "Report local user accounts, which have admin/root rights, and which can log in.",
        "linux": "Read /etc/passwd and group membership (sudo/wheel); never read /etc/shadow.",
        "windows": "Use Get-LocalUser and Get-LocalGroupMember for Administrators; never read password hashes.",
    },
    "weak_permissions": {
        "ask": "Find obviously over-permissive items: world-writable files in system paths or risky service configs.",
        "linux": "Stat key paths and report world-writable or SUID files in /etc, /usr/bin; read-only stat only.",
        "windows": "Report services whose binary path is in a user-writable location, read-only via Get-CimInstance Win32_Service.",
    },
    "firewall_status": {
        "ask": "Report whether the host firewall is enabled and summarize its default policy.",
        "linux": "Query ufw status or `nft list ruleset` / `iptables -S` read-only; do not change rules.",
        "windows": "Use Get-NetFirewallProfile to report Enabled state and default actions per profile.",
    },
    "running_services": {
        "ask": "List services/daemons set to start automatically and flag any uncommon ones.",
        "linux": "Use `systemctl list-unit-files --state=enabled` read-only.",
        "windows": "Use Get-Service / Get-CimInstance Win32_Service filtered to StartMode Auto.",
    },
}


def _platform(profile):
    """Figure out whether the target is Linux or Windows, so we can attach the
    right hint. We trust the profile's own "platform" field first, and only
    guess from the OS name as a backup."""
    platform = str(profile.get("platform", "")).lower()  # [REQUIREMENT: Casting]
    if platform in ("linux", "windows"):     # is it already one of the two values we expect?
        return platform
    return "windows" if "win" in str(profile.get("os", "")).lower() else "linux"


def _profile_summary(profile):
    """Turn the target's profile into a short bullet-point list to include in
    the prompt. We keep it small on purpose - a small AI model works much
    better with a short, focused prompt than a huge pile of data."""
    fields = ("os", "os_release", "arch", "python_version", "privilege", "tools")  # which fields to show
    lines = []                               # one formatted line per field that's actually present
    for field in fields:
        value = profile.get(field)
        if value:                            # skip anything empty or missing
            # [REQUIREMENT: Casting] cap each line's length so nothing gets too long.
            lines.append(f"- {field}: {str(value).strip()[:200]}")
    network = profile.get("network")
    if network:
        # Turn the list of network names into one comma-separated line.
        lines.append(f"- network interfaces: {', '.join(network)[:200]}")
    packages = profile.get("packages")
    if packages:
        sample = ", ".join(packages[:15])    # only show the first 15 packages
        lines.append(f"- python packages ({len(packages)} installed): {sample[:200]}")
    # Stitch the bullet points together with line breaks; show a placeholder if there's nothing to show.
    return "\n".join(lines) if lines else "- (no profile details available)"


def build_system_prompt():
    """The instructions for the AI's "role" are the same for every task, so we
    just glue the three text blocks together with a blank line between each."""
    return "\n\n".join([ROLE, SAFETY_RULES, OUTPUT_CONTRACT])


def task_keys():
    """Give back the list of task names, so main.py can loop through them
    without needing to know about the whole AUDIT_TASKS list itself."""
    return list(AUDIT_TASKS.keys())


def build_task_prompt(profile, task_key, feedback=None):
    """Build the two pieces of text we send the AI for one task: the role/rules
    text, and the specific request for this task. `feedback` is optional - it's
    left empty on the first try, and filled in with the validator's complaints
    if we're asking the AI to try again."""
    if task_key not in AUDIT_TASKS:                 # stop early if we're given a task name we don't know
        raise KeyError(f"Unknown audit task: {task_key}")

    platform = _platform(profile)                   # "linux" or "windows"
    task = AUDIT_TASKS[task_key]                     # safe to look up directly; we already checked it exists
    os_hint = LINUX_HINTS if platform == "linux" else WINDOWS_HINTS   # pick the matching hint

    # Build the request to the AI piece by piece, then join it all together at the end.
    parts = [
        "Target machine profile:\n" + _profile_summary(profile),
        os_hint,
        "Audit task: " + task["ask"],
        "Guidance: " + task[platform],
        "Write the read-only Python audit script for this one task now.",
    ]
    if feedback:                                    # only true if this is a retry
        """Tell the AI exactly what it did wrong last time, so its next attempt
        has a much better chance of passing the safety check."""
        parts.append(
            "Your previous attempt was REJECTED by the safety validator for:\n"
            + "\n".join(f"- {issue}" for issue in feedback)
            + "\nRewrite the script so it does none of these; keep it read-only."
        )
    # Return both pieces of text: the role/rules text, and the specific request (joined with blank lines).
    return build_system_prompt(), "\n\n".join(parts)
