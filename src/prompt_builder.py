"""Builds the text prompts sent to the local LLM. It does NOT contact the
API (that is ai_client.py's job).

Design notes:
- The target model is small (~8B params), so prompts are kept short, direct,
  and single-purpose. One audit task is asked per request rather than one
  giant "check everything" prompt, which an 8B model handles poorly.
- Every chunk is OS-aware. The same task carries a Linux hint and a Windows
  hint; build() picks the right one from the profile so the rest of the
  framework stays general across Windows and Linux targets.
- Safety rules are repeated in the system prompt of every request because
  small models drift from instructions over a conversation.
"""

# --- System prompt chunks (role + hard safety rules + output contract) ---

ROLE = (
    "You are a defensive security auditor. You write small, READ-ONLY Python "
    "scripts that inspect a single authorized machine and report findings. "
    "You only audit; you never change the system."
)

SAFETY_RULES = (
    "Hard rules, never break them:\n"
    "- READ-ONLY only. Never write, move, delete, or modify any file or setting.\n"
    "- No privilege escalation, no sudo/runas, no credential or token or cookie reading.\n"
    "- No persistence, no new users, no network connections to other hosts.\n"
    "- No disabling of security tools. No eval/exec of downloaded code.\n"
    "- If a check would require any of the above, skip it and note why instead."
)

OUTPUT_CONTRACT = (
    "Return ONLY a JSON object, no prose, in this exact shape:\n"
    '{"script": "<python3 source>", "explanation": "<one sentence>"}\n'
    "The script must run under python3, print human-readable findings to stdout, "
    "use only the standard library, and wrap every check in try/except so one "
    "failure never stops the rest."
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
    """Return 'windows' or 'linux' from the parsed profile, defaulting to linux."""
    value = str(profile.get("platform") or profile.get("os") or "").lower()
    return "windows" if "win" in value else "linux"


def _profile_summary(profile):
    """Compact, model-friendly summary of the target. Kept short on purpose."""
    fields = ("os", "os_release", "arch", "python_version", "tools")
    lines = []
    for field in fields:
        value = profile.get(field)
        if value:
            lines.append(f"- {field}: {str(value).strip()[:200]}")
    return "\n".join(lines) if lines else "- (no profile details available)"


def build_system_prompt():
    """Assemble the system prompt from the reusable safety chunks."""
    return "\n\n".join([ROLE, SAFETY_RULES, OUTPUT_CONTRACT])


def build_task_prompt(profile, task_key):
    """Build a single small, focused user prompt for one audit task.

    Returns (system_prompt, user_prompt). Use this to send one check per
    request so each stays within a small model's reliable context.
    """
    if task_key not in AUDIT_TASKS:
        raise KeyError(f"Unknown audit task: {task_key}")

    platform = _platform(profile)
    task = AUDIT_TASKS[task_key]
    os_hint = LINUX_HINTS if platform == "linux" else WINDOWS_HINTS

    user_prompt = "\n\n".join([
        "Target machine profile:\n" + _profile_summary(profile),
        os_hint,
        "Audit task: " + task["ask"],
        "Guidance: " + task[platform],
        "Write the read-only Python audit script for this one task now.",
    ])
    return build_system_prompt(), user_prompt


def iter_task_prompts(profile, task_keys=None):
    """Yield (task_key, system_prompt, user_prompt) for each requested task,
    or all tasks if task_keys is None. Lets the orchestrator audit a target
    one small chunk at a time."""
    for key in (task_keys or AUDIT_TASKS.keys()):
        system_prompt, user_prompt = build_task_prompt(profile, key)
        yield key, system_prompt, user_prompt


def build(profile):
    """Backward-compatible single-prompt entry point used by main.py.

    Returns (system_prompt, user_prompt) covering the full audit task list as
    a compact checklist. For an 8B model, prefer iter_task_prompts() to ask one
    chunk at a time; this combined form is the convenience/default path.
    """
    platform = _platform(profile)
    os_hint = LINUX_HINTS if platform == "linux" else WINDOWS_HINTS

    checklist = "\n".join(
        f"{i}. {task['ask']} ({task[platform]})"
        for i, task in enumerate(AUDIT_TASKS.values(), 1)
    )
    user_prompt = "\n\n".join([
        "Target machine profile:\n" + _profile_summary(profile),
        os_hint,
        "Produce ONE read-only Python audit script that performs these checks:",
        checklist,
        "Keep it compact and make each check independent.",
    ])
    return build_system_prompt(), user_prompt
