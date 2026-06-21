# validator.py - the safety gate. It scans each AI-generated script for forbidden
# behaviour BEFORE it ever runs, and drives an "ask again on failure" retry loop.

import re        # [REQUIREMENT: Module] regular expressions do all the pattern matching

DEFAULT_MAX_TRIES = 3        # how many times we re-ask the model before giving up

# A regex piece reused below. It matches the gap between a command and its
# argument in BOTH "rm -rf" (a space) and ["rm", "-rf"] (quote/comma) forms, so a
# dangerous command can't sneak past just by being written as a subprocess list.
# In regex, [\s,'"]+ means "one or more of: whitespace, comma, single or double quote".
_SEP = r"[\s,'\"]+"

# A dict mapping a category name -> (human description, list of regex fragments).
# If ANY fragment matches the script, that whole category is a hard rejection.
# r"..." is a raw string (backslashes stay literal); rf"..." is a raw f-string so
# we can embed _SEP. \b is a "word boundary" so we match whole words, not parts.
_BLOCKED_SPECS = {
    "file_deletion": ("deletes or destroys files", [
        r"\bos\.(remove|unlink|rmdir|removedirs)\s*\(",   # python file-delete calls
        r"\bshutil\.rmtree\s*\(", r"\.unlink\s*\(",        # recursive delete / pathlib unlink
        rf"\brm{_SEP}-[rf]", rf"\bdel{_SEP}/[fqs]", r"\bRemove-Item\b",  # shell deletes (unix/win)
        r"\bmkfs\b", rf"\bdd{_SEP}if=", rf"\bformat{_SEP}[a-z]:",        # disk-wiping commands
        r">\s*/dev/sd", r":\(\)\s*\{.*:\|:&.*\}", rf"\btruncate{_SEP}-s{_SEP}0\b",  # overwrite / fork bomb
    ]),
    "file_write": ("writes or modifies files (must be read-only)", [
        r"open\s*\([^)]*,\s*[\"'][^\"']*[wax+][^\"']*[\"']",  # open(..., "w"/"a"/"x"/"+") = write mode
        r"\bos\.(rename|chmod|chown|mkdir|makedirs)\s*\(",     # python filesystem changes
        r"\bshutil\.(copy|move)", r"\bSet-Content\b", r"\bAdd-Content\b",
        r"\bOut-File\b", r"\bNew-Item\b", r"\bSet-ItemProperty\b",       # PowerShell write cmdlets
    ]),
    "credential_access": ("reads credentials, keys, cookies or secrets", [
        r"/etc/shadow", r"/etc/gshadow", rf"getent{_SEP}shadow",   # password hash files
        r"id_rsa", r"id_dsa", r"id_ecdsa", r"id_ed25519",          # private SSH keys
        r"\.aws/credentials", r"\.git-credentials", r"\.netrc",    # stored credentials
        r"NTDS\.dit", r"\blsass\b", r"\bmimikatz\b",               # Windows credential dumping
        rf"reg{_SEP}save", r"hklm\\sam\b", r"Login Data", r"key4\.db",  # registry/browser secret stores
        r"logins\.json", r"places\.sqlite", r"find-generic-password",
    ]),
    "privilege_escalation": ("escalates privileges", [
        r"\bsudo\b", r"\bpkexec\b", rf"\bsu{_SEP}-", rf"\bsu{_SEP}root",  # become another/root user
        r"\bos\.setuid\s*\(", r"\bsetuid\b", r"\brunas\b",
        rf"-Verb{_SEP}RunAs", r"Start-Process[^\n]*RunAs",               # Windows "run as admin"
    ]),
    "persistence": ("installs persistence", [
        rf"\bcrontab{_SEP}-[er]\b", r"/etc/cron", rf"\bsystemctl{_SEP}enable\b",  # scheduled/startup jobs
        r"\bNew-Service\b", r"\bschtasks\b", r"\bRegister-ScheduledTask\b",
        r"rc\.local", r"CurrentVersion\\Run",                                    # boot/login auto-run
    ]),
    "security_disable": ("disables security tooling", [
        r"Set-MpPreference[^\n]*-Disable",                       # disable Windows Defender
        r"Stop-Service[^\n]*(defender|windefend)",
        rf"\bufw{_SEP}disable\b", rf"\biptables{_SEP}-F\b",      # turn off / flush the firewall
        rf"\bnft{_SEP}flush\b", rf"\bsetenforce{_SEP}0\b",       # flush nftables / disable SELinux
        rf"systemctl{_SEP}(stop|disable){_SEP}(firewalld|apparmor|auditd|ufw)",
        r"netsh[^\n]*advfirewall[^\n]*off",
    ]),
    "code_execution": ("uses dynamic code execution", [
        r"\beval\s*\(", r"\bexec\s*\(", r"\b__import__\s*\(",    # run arbitrary code from a string
        r"\bcompile\s*\(", r"pickle\.loads?\b", r"marshal\.loads?\b",  # deserialise = can execute code
    ]),
    "network": ("makes outbound network connections", [
        r"\burllib\b", r"\brequests\.", r"urlopen", r"http\.client",   # HTTP client libraries
        r"\bhttplib\b", r"\bftplib\b", r"\bsmtplib\b", r"\btelnetlib\b",
        r"socket\.create_connection", r"\.connect\s*\(", r"\bcurl\b",  # raw sockets / curl
        r"\bwget\b", r"Invoke-WebRequest", r"Invoke-RestMethod",
        rf"\bnc{_SEP}-", r"/dev/tcp/", r"\bparamiko\b",                # netcat / bash tcp / ssh
    ]),
}

# These are suspicious but NOT auto-rejected; they're recorded as warnings.
_WARNING_SPECS = {
    "shell_exec": ("runs a shell via os.system", [r"\bos\.system\s*\("]),
    "shell_true": ("uses subprocess with shell=True", [r"shell\s*=\s*True"]),
}


def _compile(specs):
    # Pre-build each category's regex ONCE (at import) for speed.
    # "|".join(fragments) puts "|" (regex OR) between the fragments, so one pattern
    # tests them all. re.IGNORECASE makes matching case-insensitive.
    return [
        (category, description, re.compile("|".join(fragments), re.IGNORECASE))
        for category, (description, fragments) in specs.items()   # unpack the (desc, fragments) tuple
    ]


# Run _compile now, at import time, so validate() just reuses the results.
_BLOCKED = _compile(_BLOCKED_SPECS)
_WARNINGS = _compile(_WARNING_SPECS)


def validate(script):
    # Inspect ONE script. Returns a dict: approved (bool), issues, warnings (lists).
    issues = []        # hard rejections (any of these means approved = False)
    warnings = []      # suspicious-but-allowed notes

    # "not script" is True for None/empty; .strip() catches whitespace-only scripts.
    if not script or not script.strip():
        return {"approved": False, "issues": ["Empty script: nothing to run."], "warnings": []}

    # Check every blocked category. pattern.search returns the first match or None.
    for category, description, pattern in _BLOCKED:
        match = pattern.search(script)
        if match:
            # match.group(0) is the exact text that matched; we quote it in the message.
            issues.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    # Same idea for warnings, but these don't block execution.
    for category, description, pattern in _WARNINGS:
        match = pattern.search(script)
        if match:
            warnings.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    # "not issues" is True when the issues list is empty -> the script is approved.
    return {"approved": not issues, "issues": issues, "warnings": warnings}


def validate_with_retries(generate, max_tries=DEFAULT_MAX_TRIES):
    # Loop: generate a script, validate it, and retry with feedback until it passes
    # or we run out of tries. "generate" is a function the caller supplies.
    attempt = None
    # A safe default validation in case generate never produces anything.
    validation = {"approved": False, "issues": ["No attempt was generated."], "warnings": []}
    feedback = None        # None on the first try; becomes the issues list on later tries

    # range(1, max_tries + 1) yields 1, 2, 3 (the attempt numbers).
    for attempt_no in range(1, max_tries + 1):
        attempt = generate(feedback) or {}     # ask for an attempt; "or {}" guards against None
        # Dig the script out of the attempt and validate it. The chained .get()s
        # return "" if any level is missing, so this never crashes.
        validation = validate(attempt.get("ai_response", {}).get("script", ""))
        if validation["approved"]:
            return _outcome(True, attempt_no, max_tries, attempt, validation)  # passed -> stop now
        feedback = validation["issues"]        # failed -> remember why, feed it into the next try

    # Loop finished without an approval: every attempt failed.
    return _outcome(False, max_tries, max_tries, attempt, validation)


def _outcome(approved, attempts, max_tries, attempt, validation):
    # Package the loop result into one consistent dict for main.py / report_writer.
    attempt = attempt or {}        # guard against None before calling .get()
    return {
        "approved": approved,
        "completed": approved,     # "completed" mirrors approved: did we end up with a usable script?
        "attempts": attempts,      # which attempt number we stopped on
        "max_tries": max_tries,
        "validation": validation,  # the final validate() result (issues/warnings)
        "ai_response": attempt.get("ai_response", {}),
        "system_prompt": attempt.get("system_prompt", ""),
        "user_prompt": attempt.get("user_prompt", ""),
    }
