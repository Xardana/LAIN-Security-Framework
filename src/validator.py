# validator.py - the SAFETY GATE. Architectural role: this is the security boundary of the
# whole project. No AI-generated script is ever executed unless it passes validate(). We use
# a deny-list of regular expressions to spot forbidden actions in the script's TEXT before it
# runs (static analysis), plus a bounded "ask the model to try again" loop.

import re        # [REQUIREMENT: Module] the regex engine. We compile patterns once and reuse them.

DEFAULT_MAX_TRIES = 3        # module constant: how many times we re-ask the model before giving up.

# WHY (logic): subprocess calls can be written two ways - as one shell string ("ufw disable")
# or as a list of args (["ufw", "disable"]). A naive "ufw disable" pattern would miss the list
# form. _SEP matches the separator in BOTH forms so a banned command can't hide by being split.
# HOW (syntax): r"..." is a RAW string (backslashes stay literal, which regex needs). The
# character class [\s,'"]+ means "one or more of: whitespace (\s), comma, single or double quote."
_SEP = r"[\s,'\"]+"

# WHY (logic): a deny-list grouped by category. Each entry is (human description, [regex pieces]).
# Keeping them as data (a dict) rather than code makes the policy easy to read and extend.
# HOW (syntax): r"..." raw strings; rf"..." is a raw f-string so we can embed the _SEP variable.
# Regex tokens used a lot below: \b = word boundary (whole-word match); \( = a literal "("
# ('(' alone means a group); [abc] = any one of those chars; | (added later) = OR.
_BLOCKED_SPECS = {
    "file_deletion": ("deletes or destroys files", [
        r"\bos\.(remove|unlink|rmdir|removedirs)\s*\(",   # (a|b|c) is an alternation group: any of those names
        r"\bshutil\.rmtree\s*\(", r"\.unlink\s*\(",
        rf"\brm{_SEP}-[rf]", rf"\bdel{_SEP}/[fqs]", r"\bRemove-Item\b",
        r"\bmkfs\b", rf"\bdd{_SEP}if=", rf"\bformat{_SEP}[a-z]:",
        r">\s*/dev/sd", r":\(\)\s*\{.*:\|:&.*\}", rf"\btruncate{_SEP}-s{_SEP}0\b",
    ]),
    "file_write": ("writes or modifies files (must be read-only)", [
        r"open\s*\([^)]*,\s*[\"'][^\"']*[wax+][^\"']*[\"']",  # detects open(..., "w"/"a"/"x"/"+") = write modes
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
        r"\bcompile\s*\(", r"pickle\.loads?\b", r"marshal\.loads?\b",  # `s?` = an optional "s" (load or loads)
    ]),
    "network": ("makes outbound network connections", [
        r"\burllib\b", r"\brequests\.", r"urlopen", r"http\.client",
        r"\bhttplib\b", r"\bftplib\b", r"\bsmtplib\b", r"\btelnetlib\b",
        r"socket\.create_connection", r"\.connect\s*\(", r"\bcurl\b",
        r"\bwget\b", r"Invoke-WebRequest", r"Invoke-RestMethod",
        rf"\bnc{_SEP}-", r"/dev/tcp/", r"\bparamiko\b",
    ]),
}

# Warnings: suspicious but NOT auto-rejected. Same structure; surfaced in the report only.
_WARNING_SPECS = {
    "shell_exec": ("runs a shell via os.system", [r"\bos\.system\s*\("]),
    "shell_true": ("uses subprocess with shell=True", [r"shell\s*=\s*True"]),
}


def _compile(specs):
    # WHY (logic): re.compile turns a pattern STRING into a reusable pattern OBJECT. Compiling
    # once at import (rather than on every validate() call) is a standard performance win.
    # HOW (syntax): this is a LIST COMPREHENSION over specs.items(). Each item is a (key, value)
    # pair, and the value is itself a (description, fragments) tuple - so `for category, (description,
    # fragments) in specs.items()` does NESTED UNPACKING in the loop header.
    #   "|".join(fragments) -> joins all of a category's regex pieces with "|" (regex OR), so one
    #                          compiled pattern matches if ANY fragment matches.
    #   re.IGNORECASE        -> a flag making the match case-insensitive.
    return [
        (category, description, re.compile("|".join(fragments), re.IGNORECASE))
        for category, (description, fragments) in specs.items()
    ]


# Run the compilation now, at import time, so validate() just reuses these ready objects.
_BLOCKED = _compile(_BLOCKED_SPECS)
_WARNINGS = _compile(_WARNING_SPECS)


def validate(script):
    # WHY (logic): inspect ONE script and return a verdict dict {approved, issues, warnings}.
    # Returning structured data (not just a bool) lets callers show WHY a script failed and feed
    # those reasons back to the model on a retry.
    issues = []        # hard rejections; ANY entry here means approved == False
    warnings = []      # suspicious-but-allowed notes

    # `not script` is True for None or "" (both falsy); .strip() catches whitespace-only scripts.
    # WHY: an empty script is never runnable, so reject immediately and skip the regex work.
    if not script or not script.strip():
        return {"approved": False, "issues": ["Empty script: nothing to run."], "warnings": []}

    # Loop over the pre-compiled blocked patterns. Each iteration UNPACKS the 3-tuple.
    for category, description, pattern in _BLOCKED:
        # pattern.search(script) scans the whole script for the FIRST match; returns a Match or None.
        match = pattern.search(script)
        if match:
            # match.group(0) is the ENTIRE matched substring (group 0 = the whole match). We quote
            # it in the message so the user sees exactly what tripped the rule.
            issues.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    # Same scan for warnings, but these do NOT block execution.
    for category, description, pattern in _WARNINGS:
        match = pattern.search(script)
        if match:
            warnings.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    # `not issues` is True when the list is EMPTY (an empty list is falsy). So approved == "no issues found."
    return {"approved": not issues, "issues": issues, "warnings": warnings}


def validate_with_retries(generate, max_tries=DEFAULT_MAX_TRIES):
    # WHY (logic): a "generate, check, repeat-on-failure" control loop. KEY DESIGN: `generate`
    # is a CALLBACK FUNCTION passed in by the caller (this is dependency injection). The validator
    # decides WHEN to ask for another attempt; the caller owns HOW an attempt is produced (it calls
    # the LLM). This keeps the validator free of any AI/network dependency.
    attempt = None
    # A safe default verdict, in case `generate` ever yields nothing usable.
    validation = {"approved": False, "issues": ["No attempt was generated."], "warnings": []}
    feedback = None        # None on the first call; becomes the issues list on later calls

    # range(1, max_tries + 1) produces the integers 1, 2, 3 (the stop value is EXCLUSIVE, so +1).
    for attempt_no in range(1, max_tries + 1):
        # Call the injected function. `generate(feedback) or {}` substitutes an empty dict if it
        # returns None, so the .get() chain below can't crash.
        attempt = generate(feedback) or {}
        # CHAINED .get() with defaults: attempt.get("ai_response", {}) returns the response dict (or
        # {}), then .get("script", "") returns the script text (or ""). This safely digs through a
        # nested structure that might be missing levels - no KeyError possible.
        validation = validate(attempt.get("ai_response", {}).get("script", ""))
        if validation["approved"]:
            return _outcome(True, attempt_no, max_tries, attempt, validation)  # success: stop now
        feedback = validation["issues"]        # failure: remember the reasons for the next prompt

    # The for-loop finished without returning -> every attempt failed validation.
    return _outcome(False, max_tries, max_tries, attempt, validation)


def _outcome(approved, attempts, max_tries, attempt, validation):
    # WHY (logic): a tiny factory that packs the loop result into ONE consistent dict, so main.py
    # and report_writer always receive the same keys regardless of success or failure.
    attempt = attempt or {}        # guard against None before the .get() calls
    return {
        "approved": approved,
        "completed": approved,     # alias: "did we end with a usable, approved script?"
        "attempts": attempts,      # which attempt number we stopped on
        "max_tries": max_tries,
        "validation": validation,  # the final verdict (issues/warnings) for the report
        "ai_response": attempt.get("ai_response", {}),
        "system_prompt": attempt.get("system_prompt", ""),
        "user_prompt": attempt.get("user_prompt", ""),
    }
