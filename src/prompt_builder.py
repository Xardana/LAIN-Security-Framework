# prompt_builder.py - assembles the text prompts sent to the LLM. Architectural role:
# this is "prompt engineering as code." It contains ZERO networking (ai_client does that)
# and ZERO logic that runs scripts - it only builds strings. Separating prompt text from
# the transport makes prompts easy to tune and test in isolation. Prompts are kept small
# and single-purpose because the target model is small (~8B parameters).

# --- The system prompt is built from three constant strings joined per request. ---
# WHY constants: defining them once at module level means the exact same wording is reused
# on every call, which keeps the model's behaviour consistent and the code DRY.
# Syntax note: wrapping string literals in ( ... ) and placing them adjacent makes Python
# AUTOMATICALLY concatenate them at compile time into one string - a clean way to write
# long text without "+" on every line.

ROLE = (
    "You are a defensive security auditor working on an explicitly authorized, "
    "read-only audit. You write small READ-ONLY Python scripts that inspect a "
    "single authorized machine and report findings. You only audit; you never "
    "change the system and you never produce exploit code."
)

# The "\n" sequences are newline ESCAPE characters - they become real line breaks in the
# final string, formatting the rules as a bullet list the model reads clearly.
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

# WHY a fixed output schema: by forcing the generated SCRIPT to print this exact JSON shape,
# report_writer can parse every task identically instead of guessing at free-form text.
# This is a "contract" between the AI output and our parser.
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

# Note the "+ FINDINGS_SCHEMA" at the end: this is runtime string CONCATENATION with "+",
# gluing the schema constant onto the end of this contract description.
OUTPUT_CONTRACT = (
    "Reply with ONLY a JSON object, no prose, in this exact shape:\n"
    '{"script": "<python3 source>", "explanation": "<one sentence>"}\n'
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

# --- The audit catalogue: a DICT OF DICTS. Outer key = task name; inner dict holds the
# task's "ask" plus a Linux and a Windows hint. WHY this structure: it's a lookup table that
# keeps each task's data together and lets us add/remove tasks without touching the code logic.
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
    # WHY (logic): pick the right OS hint. We trust system_profile's normalised "platform"
    # field first and only "sniff" the os string as a fallback for older data.
    # HOW (syntax): str(...) is a defensive CAST [REQUIREMENT: Casting] so .lower() works even
    # if "platform" is missing (None). dict.get("platform", "") returns "" when absent.
    platform = str(profile.get("platform", "")).lower()
    if platform in ("linux", "windows"):     # membership test against a tuple of valid values
        return platform
    return "windows" if "win" in str(profile.get("os", "")).lower() else "linux"


def _profile_summary(profile):
    # WHY (logic): compress the profile into a short bullet list for the prompt. We keep it
    # SMALL on purpose - a small model handles a tight prompt far better than a huge data dump.
    fields = ("os", "os_release", "arch", "python_version", "privilege", "tools")  # tuple of keys to show
    lines = []                               # we collect one formatted line per present field
    for field in fields:
        value = profile.get(field)
        if value:                            # skip empty/missing fields
            # str(value) CAST [REQUIREMENT: Casting] lets us call .strip() and SLICE it.
            # [:200] is slice syntax: "from start up to index 200" - caps each line's length.
            lines.append(f"- {field}: {str(value).strip()[:200]}")
    network = profile.get("network")
    if network:
        # ", ".join(list) is the standard idiom to turn a list of strings into one comma-
        # separated string. UNDER THE HOOD join walks the list inserting the separator between items.
        lines.append(f"- network interfaces: {', '.join(network)[:200]}")
    packages = profile.get("packages")
    if packages:
        sample = ", ".join(packages[:15])    # packages[:15] slices the FIRST 15 items only
        # len(packages) returns the item count; we show the count plus a short sample, not all of them.
        lines.append(f"- python packages ({len(packages)} installed): {sample[:200]}")
    # "\n".join(lines) glues the bullets with newlines. Ternary: if lines is empty (falsy),
    # use a placeholder string instead.
    return "\n".join(lines) if lines else "- (no profile details available)"


def build_system_prompt():
    # WHY (logic): the system prompt is identical for every task, so we build it from the
    # three constants here. "\n\n".join([...]) joins the list with a BLANK line between each
    # part, visually separating role / rules / output-contract for the model.
    return "\n\n".join([ROLE, SAFETY_RULES, OUTPUT_CONTRACT])


def task_keys():
    # WHY (logic): expose the task names so main.py can loop over them without importing the
    # whole AUDIT_TASKS dict. list(dict.keys()) materialises the keys VIEW into a real list.
    return list(AUDIT_TASKS.keys())


def build_task_prompt(profile, task_key, feedback=None):
    # WHY (logic): build the (system, user) prompt pair for ONE task. `feedback=None` is a
    # DEFAULT ARGUMENT - callers can omit it (first attempt) or pass the validator's complaints
    # (a retry). Returning a TUPLE lets the caller unpack both prompts in one line.
    if task_key not in AUDIT_TASKS:                 # guard: reject unknown task names early
        # `raise` throws an exception, stopping execution and signalling a programming error.
        raise KeyError(f"Unknown audit task: {task_key}")

    platform = _platform(profile)                   # "linux" or "windows"
    task = AUDIT_TASKS[task_key]                     # [] lookup; safe here because we checked membership above
    os_hint = LINUX_HINTS if platform == "linux" else WINDOWS_HINTS   # ternary picks the matching hint

    # Build the user message as a LIST of sections; joining at the end is cheaper and cleaner
    # than concatenating strings repeatedly. task["ask"]/task[platform] index into the inner dict.
    parts = [
        "Target machine profile:\n" + _profile_summary(profile),
        os_hint,
        "Audit task: " + task["ask"],
        "Guidance: " + task[platform],
        "Write the read-only Python audit script for this one task now.",
    ]
    if feedback:                                    # truthy only on a retry (a non-empty list)
        # GENERATOR EXPRESSION inside join: "f'- {issue}' for issue in feedback" yields one
        # "- <issue>" line per item, and "\n".join(...) stitches them with newlines. WHY: telling
        # the model exactly what it did wrong dramatically improves the next attempt.
        parts.append(
            "Your previous attempt was REJECTED by the safety validator for:\n"
            + "\n".join(f"- {issue}" for issue in feedback)
            + "\nRewrite the script so it does none of these; keep it read-only."
        )
    # Return BOTH prompts: the system prompt and the user prompt (parts joined by blank lines).
    return build_system_prompt(), "\n\n".join(parts)
