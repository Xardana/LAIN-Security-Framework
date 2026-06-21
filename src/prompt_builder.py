# prompt_builder.py - builds the text prompts sent to the LLM. It only assembles
# strings; ai_client.py is what actually sends them. Prompts are kept small and
# single-purpose because the target model is small (~8B parameters).

# --- System-prompt pieces: three constant strings joined together per request ---

# ROLE tells the model who it is. Repeated every request so it never forgets.
ROLE = (
    "You are a defensive security auditor working on an explicitly authorized, "
    "read-only audit. You write small READ-ONLY Python scripts that inspect a "
    "single authorized machine and report findings. You only audit; you never "
    "change the system and you never produce exploit code."
)

# SAFETY_RULES is the hard "never do this" list. Small models drift over a long
# conversation, so these rules are re-sent on every single request.
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

# FINDINGS_SCHEMA is the exact JSON shape the generated script must PRINT when it
# runs. Fixing this shape lets report_writer render one consistent PDF template.
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

# OUTPUT_CONTRACT describes the REPLY shape (a {"script","explanation"} wrapper).
# The "+ FINDINGS_SCHEMA" concatenates the schema string onto the end.
OUTPUT_CONTRACT = (
    "Reply with ONLY a JSON object, no prose, in this exact shape:\n"
    '{"script": "<python3 source>", "explanation": "<one sentence>"}\n'
    "The script must run under python3, use only the standard library, and wrap "
    "every check in try/except so one failure never stops the rest. The script "
    "must print EXACTLY ONE JSON object to stdout and nothing else, in this "
    "shape:\n" + FINDINGS_SCHEMA
)

# --- Per-OS guidance: which one we attach depends on the detected platform ---

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

# --- The audit tasks: a dict of small, specific checks, asked one at a time ---
# Each task has an "ask" (what to do) plus a "linux"/"windows" hint (how to do it
# on that OS). One task per request keeps each prompt small for the 8B model.
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
    # Return "windows" or "linux" so we attach the right OS hint.
    # [REQUIREMENT: Casting] str(...) guards a missing field so .lower() always works.
    platform = str(profile.get("platform", "")).lower()
    if platform in ("linux", "windows"):     # system_profile already normalised it -> trust it
        return platform
    # Fallback for an older profile without a "platform" field: sniff the os string.
    return "windows" if "win" in str(profile.get("os", "")).lower() else "linux"


def _profile_summary(profile):
    # Build a short bullet list describing the target, to drop into the prompt.
    fields = ("os", "os_release", "arch", "python_version", "privilege", "tools")  # tuple of keys to show
    lines = []                               # we collect one "- key: value" string per field
    for field in fields:
        value = profile.get(field)
        if value:                            # skip fields that are empty/missing
            # [REQUIREMENT: Casting] str(value) lets us .strip() and slice [:200]
            # (keep the first 200 chars) regardless of the value's real type.
            lines.append(f"- {field}: {str(value).strip()[:200]}")
    network = profile.get("network")
    if network:
        # ", ".join(list) glues the interface names into one comma-separated string.
        lines.append(f"- network interfaces: {', '.join(network)[:200]}")
    packages = profile.get("packages")
    if packages:
        sample = ", ".join(packages[:15])    # [:15] = only the first 15 names, to stay small
        # len(packages) is the total count; we show count + sample, not the full list.
        lines.append(f"- python packages ({len(packages)} installed): {sample[:200]}")
    # "\n".join(lines) joins the bullets with newlines; if lines is empty use a placeholder.
    return "\n".join(lines) if lines else "- (no profile details available)"


def build_system_prompt():
    # Glue the three system-prompt constants together with blank lines between them.
    return "\n\n".join([ROLE, SAFETY_RULES, OUTPUT_CONTRACT])


def task_keys():
    # Return the task names as a list so main.py can loop over them.
    # list(dict.keys()) makes a real list from the dict's keys.
    return list(AUDIT_TASKS.keys())


def build_task_prompt(profile, task_key, feedback=None):
    # Build the (system_prompt, user_prompt) pair for ONE task. feedback is None
    # the first time, or the validator's complaints on a retry.
    if task_key not in AUDIT_TASKS:                 # guard against an unknown task name
        raise KeyError(f"Unknown audit task: {task_key}")   # raise = stop with an error

    platform = _platform(profile)                   # "linux" or "windows"
    task = AUDIT_TASKS[task_key]                     # the dict for this specific task
    # Pick the matching OS hint with a ternary expression.
    os_hint = LINUX_HINTS if platform == "linux" else WINDOWS_HINTS

    # Build the user message as a list of sections; we join them at the end.
    parts = [
        "Target machine profile:\n" + _profile_summary(profile),  # who the target is
        os_hint,                                                  # how to approach this OS
        "Audit task: " + task["ask"],                            # what to check
        "Guidance: " + task[platform],                           # OS-specific how-to for this task
        "Write the read-only Python audit script for this one task now.",
    ]
    if feedback:                                    # only present on a retry
        # Append a section listing each rejection reason so the model can fix them.
        # The inner "\n".join(...) turns the issues list into "- issue" lines.
        parts.append(
            "Your previous attempt was REJECTED by the safety validator for:\n"
            + "\n".join(f"- {issue}" for issue in feedback)
            + "\nRewrite the script so it does none of these; keep it read-only."
        )
    # Return the system prompt plus the user prompt (sections joined by blank lines).
    return build_system_prompt(), "\n\n".join(parts)
