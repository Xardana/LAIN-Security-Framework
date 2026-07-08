"""
validator.py is the safety gate. This is the security boundary of the whole
project - no AI-generated script is ever run unless it passes validate()
first. We check the script's text against a list of banned patterns before it
ever runs, and give the AI a limited number of chances to fix its mistakes
and try again.
"""

import re        # [REQUIREMENT: Module] the regex engine. We build each pattern once and reuse it.

DEFAULT_MAX_TRIES = 3        # how many times we'll ask the AI to try again before giving up.

"""A command can be written as one shell string ("ufw disable") or as a list
of separate pieces (["ufw", "disable"]). This pattern matches the gap between
words in either style, so a banned command can't sneak past just by being
split up differently."""
_SEP = r"[\s,'\"]+"

"""This is our list of banned patterns, grouped by category. Each entry pairs
a short description with a list of regex patterns to check for. Keeping this
as plain data (instead of scattered checks in code) makes the rules easy to
read and easy to add to later."""
_BLOCKED_SPECS = {
    "file_deletion": ("deletes or destroys files", [
        r"\bos\.(remove|unlink|rmdir|removedirs)\s*\(",
        r"\bshutil\.rmtree\s*\(", r"\.unlink\s*\(",
        rf"\brm{_SEP}-[rf]", rf"\bdel{_SEP}/[fqs]", r"\bRemove-Item\b",
        r"\bmkfs\b", rf"\bdd{_SEP}if=", rf"\bformat{_SEP}[a-z]:",
        r">\s*/dev/sd", r":\(\)\s*\{.*:\|:&.*\}", rf"\btruncate{_SEP}-s{_SEP}0\b",
    ]),
    "file_write": ("writes or modifies files (must be read-only)", [
        r"open\s*\([^)]*,\s*[\"'][^\"']*[wax+][^\"']*[\"']",  # catches open(..., "w"/"a"/"x"/"+") write modes
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

# Suspicious, but not automatically rejected - these just get mentioned in the report.
_WARNING_SPECS = {
    "shell_exec": ("runs a shell via os.system", [r"\bos\.system\s*\("]),
    "shell_true": ("uses subprocess with shell=True", [r"shell\s*=\s*True"]),
}


def _compile(specs):
    """Turn each category's list of pattern pieces into one ready-to-use regex
    pattern object. Doing this once, right when the file loads, is faster
    than rebuilding the patterns every single time validate() runs."""
    return [
        (category, description, re.compile("|".join(fragments), re.IGNORECASE))
        for category, (description, fragments) in specs.items()
    ]


# Build the pattern objects now, once, so validate() can just reuse them every time.
_BLOCKED = _compile(_BLOCKED_SPECS)
_WARNINGS = _compile(_WARNING_SPECS)


def validate(script):
    """Check one script and give back a verdict: whether it's approved, and
    why or why not. Giving back the actual reasons (not just yes/no) lets us
    show the AI what it did wrong, so it can try again."""
    issues = []        # anything found here means the script is rejected
    warnings = []      # suspicious, but still allowed

    # An empty script can never be run, so reject it right away without checking anything else.
    if not script or not script.strip():
        return {"approved": False, "issues": ["Empty script: nothing to run."], "warnings": []}

    # Check the script against every banned pattern.
    for category, description, pattern in _BLOCKED:
        match = pattern.search(script)
        if match:
            # Quote exactly what matched, so whoever reads this can see precisely what tripped the rule.
            issues.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    # Same check, but for the "suspicious, not blocking" list.
    for category, description, pattern in _WARNINGS:
        match = pattern.search(script)
        if match:
            warnings.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    # Approved only if we found no issues at all.
    return {"approved": not issues, "issues": issues, "warnings": warnings}


def validate_with_retries(generate, max_tries=DEFAULT_MAX_TRIES):
    """Ask the AI for a script, check it, and if it fails, ask again with
    feedback about what went wrong - up to a limited number of times.
    `generate` is a function handed to us by the caller; it does the actual
    talking to the AI, so this file never needs to know anything about that."""
    attempt = None
    # A safe fallback verdict, in case `generate` ever gives us back nothing usable.
    validation = {"approved": False, "issues": ["No attempt was generated."], "warnings": []}
    feedback = None        # empty on the first try; filled in with the issues list on later tries

    for attempt_no in range(1, max_tries + 1):
        # Ask for one attempt. If nothing comes back, just treat it as an empty result.
        attempt = generate(feedback) or {}
        # Dig into the attempt for its script text, safely falling back to "" at every step
        # if something's missing, so this can never crash on an incomplete reply.
        validation = validate(attempt.get("ai_response", {}).get("script", ""))
        if validation["approved"]:
            return _outcome(True, attempt_no, max_tries, attempt, validation)  # success, stop here
        feedback = validation["issues"]        # failed: remember why, so the next prompt can address it

    # We ran out of tries without ever getting an approved script.
    return _outcome(False, max_tries, max_tries, attempt, validation)


def _outcome(approved, attempts, max_tries, attempt, validation):
    """Package up the result of the retry loop into one consistent dict, so
    main.py and report_writer always get the same set of fields back,
    whether the run succeeded or failed."""
    attempt = attempt or {}        # guard against a missing attempt before reading its fields
    return {
        "approved": approved,
        "completed": approved,     # another name for "did we end up with a usable, approved script?"
        "attempts": attempts,      # which attempt number we stopped on
        "max_tries": max_tries,
        "validation": validation,  # the final verdict (issues/warnings) for the report
        "ai_response": attempt.get("ai_response", {}),
        "system_prompt": attempt.get("system_prompt", ""),
        "user_prompt": attempt.get("user_prompt", ""),
    }
