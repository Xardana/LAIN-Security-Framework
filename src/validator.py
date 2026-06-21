"""Checks AI-generated audit scripts for blocked behavior before anything is
executed on a target, and drives a bounded regenerate-and-recheck loop.

validate() is the gate: it never imports the LLM or touches the network, it
just inspects script text and returns {"approved", "issues", "warnings"}.

validate_with_retries() owns the retry policy the orchestrator wants: ask the
AI again (with the validator's complaints fed back) until a script passes or
DEFAULT_MAX_TRIES is reached. If every attempt fails it returns an outcome
flagged completed=False so report_writer can render a clear "could not
complete" section instead of a blank one.
"""

import re

DEFAULT_MAX_TRIES = 3

# Separator between a command and its argument. Matches a plain space ("rm -rf")
# as well as the quote/comma form of subprocess list args (["rm", "-rf"]), so a
# dangerous command can't slip past just by being split into a list.
_SEP = r"[\s,'\"]+"

# category -> (human description, list of alternative regex fragments). A single
# match blocks the script; these map to the framework's forbidden actions.
_BLOCKED_SPECS = {
    "file_deletion": ("deletes or destroys files", [
        r"\bos\.(remove|unlink|rmdir|removedirs)\s*\(",
        r"\bshutil\.rmtree\s*\(", r"\.unlink\s*\(",
        rf"\brm{_SEP}-[rf]", rf"\bdel{_SEP}/[fqs]", r"\bRemove-Item\b",
        r"\bmkfs\b", rf"\bdd{_SEP}if=", rf"\bformat{_SEP}[a-z]:",
        r">\s*/dev/sd", r":\(\)\s*\{.*:\|:&.*\}", rf"\btruncate{_SEP}-s{_SEP}0\b",
    ]),
    "file_write": ("writes or modifies files (must be read-only)", [
        r"open\s*\([^)]*,\s*[\"'][^\"']*[wax+][^\"']*[\"']",
        r"\bos\.(rename|chmod|chown|mkdir|makedirs)\s*\(",
        r"\bshutil\.(copy|move)", r"\bSet-Content\b", r"\bAdd-Content\b",
        r"\bOut-File\b", r"\bNew-Item\b", r"\bSet-ItemProperty\b",
    ]),
    "credential_access": ("reads credentials, keys, cookies or secrets", [
        r"/etc/shadow", r"/etc/gshadow", rf"getent{_SEP}shadow",
        r"id_rsa", r"id_dsa", r"id_ecdsa", r"id_ed25519",
        r"\.aws/credentials", r"\.git-credentials", r"\.netrc",
        r"NTDS\.dit", r"\blsass\b", r"\bmimikatz\b",
        rf"reg{_SEP}save", r"hklm\\sam\b", r"Login Data", r"key4\.db",
        r"logins\.json", r"places\.sqlite", r"find-generic-password",
    ]),
    "privilege_escalation": ("escalates privileges", [
        r"\bsudo\b", r"\bpkexec\b", rf"\bsu{_SEP}-", rf"\bsu{_SEP}root",
        r"\bos\.setuid\s*\(", r"\bsetuid\b", r"\brunas\b",
        rf"-Verb{_SEP}RunAs", r"Start-Process[^\n]*RunAs",
    ]),
    "persistence": ("installs persistence", [
        rf"\bcrontab{_SEP}-[er]\b", r"/etc/cron", rf"\bsystemctl{_SEP}enable\b",
        r"\bNew-Service\b", r"\bschtasks\b", r"\bRegister-ScheduledTask\b",
        r"rc\.local", r"CurrentVersion\\Run",
    ]),
    "security_disable": ("disables security tooling", [
        r"Set-MpPreference[^\n]*-Disable",
        r"Stop-Service[^\n]*(defender|windefend)",
        rf"\bufw{_SEP}disable\b", rf"\biptables{_SEP}-F\b",
        rf"\bnft{_SEP}flush\b", rf"\bsetenforce{_SEP}0\b",
        rf"systemctl{_SEP}(stop|disable){_SEP}(firewalld|apparmor|auditd|ufw)",
        r"netsh[^\n]*advfirewall[^\n]*off",
    ]),
    "code_execution": ("uses dynamic code execution", [
        r"\beval\s*\(", r"\bexec\s*\(", r"\b__import__\s*\(",
        r"\bcompile\s*\(", r"pickle\.loads?\b", r"marshal\.loads?\b",
    ]),
    "network": ("makes outbound network connections", [
        r"\burllib\b", r"\brequests\.", r"urlopen", r"http\.client",
        r"\bhttplib\b", r"\bftplib\b", r"\bsmtplib\b", r"\btelnetlib\b",
        r"socket\.create_connection", r"\.connect\s*\(", r"\bcurl\b",
        r"\bwget\b", r"Invoke-WebRequest", r"Invoke-RestMethod",
        rf"\bnc{_SEP}-", r"/dev/tcp/", r"\bparamiko\b",
    ]),
}

# Suspicious but not auto-blocked: surfaced for the report, not a rejection.
_WARNING_SPECS = {
    "shell_exec": ("runs a shell via os.system", [r"\bos\.system\s*\("]),
    "shell_true": ("uses subprocess with shell=True", [r"shell\s*=\s*True"]),
}


def _compile(specs):
    return [
        (category, description, re.compile("|".join(fragments), re.IGNORECASE))
        for category, (description, fragments) in specs.items()
    ]


_BLOCKED = _compile(_BLOCKED_SPECS)
_WARNINGS = _compile(_WARNING_SPECS)


def validate(script):
    """Inspect a script and return {"approved", "issues", "warnings"}.

    approved is True only when no blocked pattern matches. issues/warnings are
    human-readable strings (also fed back to the model on a retry).
    """
    issues = []
    warnings = []

    if not script or not script.strip():
        return {"approved": False, "issues": ["Empty script: nothing to run."], "warnings": []}

    for category, description, pattern in _BLOCKED:
        match = pattern.search(script)
        if match:
            issues.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    for category, description, pattern in _WARNINGS:
        match = pattern.search(script)
        if match:
            warnings.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    return {"approved": not issues, "issues": issues, "warnings": warnings}


def validate_with_retries(generate, max_tries=DEFAULT_MAX_TRIES):
    """Regenerate-and-recheck loop.

    generate(feedback) must produce one attempt as a dict containing at least
    "ai_response" (with a "script" key); "system_prompt"/"user_prompt" are
    carried through to the outcome for the report. On the first call feedback
    is None; on later calls it is the list of validator issues from the last
    failed attempt, so the prompt can tell the model what to fix.

    Returns an outcome dict:
        {"approved", "completed", "attempts", "max_tries",
         "validation", "ai_response", "system_prompt", "user_prompt"}
    completed is False when every attempt failed validation.
    """
    attempt = None
    validation = {"approved": False, "issues": ["No attempt was generated."], "warnings": []}
    feedback = None

    for attempt_no in range(1, max_tries + 1):
        attempt = generate(feedback) or {}
        validation = validate(attempt.get("ai_response", {}).get("script", ""))
        if validation["approved"]:
            return _outcome(True, attempt_no, max_tries, attempt, validation)
        feedback = validation["issues"]

    return _outcome(False, max_tries, max_tries, attempt, validation)


def _outcome(approved, attempts, max_tries, attempt, validation):
    attempt = attempt or {}
    return {
        "approved": approved,
        "completed": approved,
        "attempts": attempts,
        "max_tries": max_tries,
        "validation": validation,
        "ai_response": attempt.get("ai_response", {}),
        "system_prompt": attempt.get("system_prompt", ""),
        "user_prompt": attempt.get("user_prompt", ""),
    }
