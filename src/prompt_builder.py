"""
prompt_builder.py
=================
Single responsibility: build the text prompts that get sent to the local LLM.
It does NOT contact the API (that is ai_client.py's job) - it only assembles
strings.

Design notes:
- The target model is small (~8B params), so prompts are kept short, direct,
  and single-purpose. One audit task is asked per request rather than one giant
  "check everything" prompt, which an 8B model handles poorly.
- Every task chunk is OS-aware. The same task carries a Linux hint and a Windows
  hint; the builder picks the right one from the profile so the framework stays
  general across Windows and Linux targets.
- The safety rules are repeated in the system prompt of every request because
  small models tend to drift from instructions over a long conversation.

Coding requirements demonstrated in THIS file:
    * Functions - each prompt-building step is its own def.
    * Casting   - profile values are wrapped in str(...) before slicing/joining,
                  so a missing or non-string field can never crash prompt building.
"""

# --- System prompt chunks (role + hard safety rules + output contract) ---

ROLE = (
    "You are a defensive security auditor working on an explicitly authorized, "
    "read-only audit. You write small READ-ONLY Python scripts that inspect a "
    "single authorized machine and report findings. You only audit; you never "
    "change the system and you never produce exploit code."
)

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

# The exact JSON shape every generated script must print to stdout. Keeping
# this fixed lets report_writer.py render one standardized PDF template for
# every task without guessing at free-form text.
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

OUTPUT_CONTRACT = (
    "Reply with ONLY a JSON object, no prose, in this exact shape:\n"
    '{"script": "<python3 source>", "explanation": "<one sentence>"}\n'
    "The script must run under python3, use only the standard library, and wrap "
    "every check in try/except so one failure never stops the rest. The script "
    "must print EXACTLY ONE JSON object to stdout and nothing else, in this "
    "shape:\n" + FINDINGS_SCHEMA
)

# --- Per-OS guidance chunks ---

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

# --- Audit task chunks: small, specific, OS-aware checks ---
# Each can be asked on its own so the request stays small for an 8B model.

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
    """Return 'windows' or 'linux' for OS-specific prompt selection.

    system_profile.parse() already normalizes the detected OS into a 'platform'
    field, so we trust that authoritative value; we only fall back to sniffing
    the raw os string if an older profile lacks that field.
    """
    # [REQUIREMENT: Casting] str(...) guards against a missing/None field so
    # .lower() always works, even before we know the value's real type.
    platform = str(profile.get("platform", "")).lower()
    if platform in ("linux", "windows"):
        return platform
    return "windows" if "win" in str(profile.get("os", "")).lower() else "linux"


def _profile_summary(profile):
    """Compact, model-friendly summary of the target. Kept short on purpose:
    interface names and a package count/sample are included, but the full
    package list is left out so the prompt stays small for an 8B model."""
    fields = ("os", "os_release", "arch", "python_version", "privilege", "tools")
    lines = []
    for field in fields:
        value = profile.get(field)
        if value:
            # [REQUIREMENT: Casting] str(value) lets us safely .strip() and slice
            # the value to 200 chars regardless of its original type.
            lines.append(f"- {field}: {str(value).strip()[:200]}")
    network = profile.get("network")
    if network:
        lines.append(f"- network interfaces: {', '.join(network)[:200]}")
    packages = profile.get("packages")
    if packages:
        # Show only a count plus the first 15 names so the prompt stays small.
        sample = ", ".join(packages[:15])
        lines.append(f"- python packages ({len(packages)} installed): {sample[:200]}")
    return "\n".join(lines) if lines else "- (no profile details available)"


def build_system_prompt():
    """Assemble the system prompt (role + safety rules + output contract).

    These three reusable text chunks are joined into the "system" message that
    is sent on every single request, so the model is always reminded of who it
    is, what it must never do, and exactly what JSON shape to return.
    """
    return "\n\n".join([ROLE, SAFETY_RULES, OUTPUT_CONTRACT])


def task_keys():
    """Return the list of audit task names the orchestrator should run.

    main.py loops over these keys, asking the model for one script per task.
    """
    return list(AUDIT_TASKS.keys())


def build_task_prompt(profile, task_key, feedback=None):
    """Build the (system_prompt, user_prompt) pair for ONE audit task.

    This is the main function other modules call. Sending one task per request
    keeps each prompt small enough for the 8B model to handle reliably.

    `feedback`, when given, is the list of validator issues from a rejected
    previous attempt; it is appended so the model knows what to fix on a retry.
    """
    # Fail loudly on an unknown task name rather than silently building junk.
    if task_key not in AUDIT_TASKS:
        raise KeyError(f"Unknown audit task: {task_key}")

    # Choose the Linux or Windows guidance based on the detected platform.
    platform = _platform(profile)
    task = AUDIT_TASKS[task_key]
    os_hint = LINUX_HINTS if platform == "linux" else WINDOWS_HINTS

    # Assemble the user message piece by piece, then join with blank lines.
    parts = [
        "Target machine profile:\n" + _profile_summary(profile),
        os_hint,
        "Audit task: " + task["ask"],
        "Guidance: " + task[platform],
        "Write the read-only Python audit script for this one task now.",
    ]
    if feedback:
        parts.append(
            "Your previous attempt was REJECTED by the safety validator for:\n"
            + "\n".join(f"- {issue}" for issue in feedback)
            + "\nRewrite the script so it does none of these; keep it read-only."
        )
    return build_system_prompt(), "\n\n".join(parts)
