"""
This is the safety gate for the old way of working, where the AI wrote a script
and we ran it on the target. Before any such script runs, it has to pass validate()
here. We scan the text for banned patterns, and give the AI a few tries to fix
itself. The main program doesn't use this path anymore, but we keep it around, both
as the "before" half of our comparison and because it still guards the script path
if anyone runs it.
"""

import ast        # reads Python as structure, so we can tell real code from plain prose.
import io         # lets us hand a string to something that wants a file.
import re         # [REQUIREMENT: Module] the regex engine. We build each pattern once and reuse it.
import tokenize   # breaks Python into labelled pieces, so we can find the comments.

DEFAULT_MAX_TRIES = 3        # how many times we let the AI try again before giving up.

# A command can be one shell string ("ufw disable") or a list of pieces
# (["ufw", "disable"]). This matches the gap between words either way, so a banned
# command can't slip past just by being split up differently.
_SEP = r"[\s,'\"]+"

# Our banned patterns, grouped by category. Each entry is a short description plus a
# list of regexes to look for. Keeping it as plain data instead of scattered if-checks
# makes the rules easy to read and easy to add to later.
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
        # We used to ban the bare word "sudo", but that's too blunt. An audit script is
        # meant to report who's in the sudo group, and just naming it got the whole
        # script thrown out. What matters is sudo actually being run. These two patterns
        # catch sudo at the front of a command ("sudo -l") and sudo handed to subprocess
        # as the thing to run (["sudo", "-l"]), and leave harmless mentions alone.
        r"[\"']sudo\s+\S",
        r"(?:run|call|Popen|check_output|check_call|system)\s*\(\s*\[?\s*[\"']sudo\b",
        r"\bpkexec\b", rf"\bsu{_SEP}-", rf"\bsu{_SEP}root",
        # Same idea: actually calling setuid is the problem. Just reporting which files
        # have the SUID bit set is exactly the read-only check we wanted.
        r"\bos\.setuid\s*\(", r"\bos\.setgid\s*\(", r"\brunas\b",
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
        # The dangerous one is a bare compile("...") feeding exec. The "(?<![.\w])" part
        # means "as long as there's no dot or letter right before it", which lets
        # re.compile() through. Nearly every audit script needs regex to read command
        # output, and the old rule rejected all of them.
        r"(?<![.\w])compile\s*\(",
        r"pickle\.loads?\b", r"marshal\.loads?\b",
    ]),
    "network": ("makes outbound network connections", [
        r"\burllib\b", r"\brequests\.", r"urlopen", r"http\.client",
        r"\bhttplib\b", r"\bftplib\b", r"\bsmtplib\b", r"\btelnetlib\b",
        # Opening a socket at all gives it away, a read-only audit never needs one. We
        # used to match any ".connect(", which also flagged harmless things like
        # sqlite3.connect("file.db"). A real socket connects to a (host, port) pair, so
        # we look for the double bracket instead.
        r"socket\.socket\s*\(", r"socket\.create_connection", r"\.connect\s*\(\s*\(",
        r"\bcurl\b", r"\bwget\b", r"Invoke-WebRequest", r"Invoke-RestMethod",
        rf"\bnc{_SEP}-", r"/dev/tcp/", r"\bparamiko\b",
    ]),
}

# Suspicious but not an outright reject. These just get noted in the report.
_WARNING_SPECS = {
    "shell_exec": ("runs a shell via os.system", [r"\bos\.system\s*\("]),
    "shell_true": ("uses subprocess with shell=True", [r"shell\s*=\s*True"]),
}


def _compile(specs):
    """Turn each category's list of pattern pieces into one ready-to-go regex. Doing
    this once when the file loads is faster than rebuilding them every validate()."""
    return [
        (category, description, re.compile("|".join(fragments), re.IGNORECASE))
        for category, (description, fragments) in specs.items()
    ]


# Build the patterns once, up front, so validate() just reuses them.
_BLOCKED = _compile(_BLOCKED_SPECS)
_WARNINGS = _compile(_WARNING_SPECS)


def _strip_comments(script):
    """Comments are notes for people, they never run. Our patterns above can't tell
    the difference, so an innocent note like "# this never calls rm -rf" would get the
    whole script rejected. Blank the comments out first, so we only judge code that
    actually runs."""
    try:
        # Walk the script and label every piece: a name, a number, a string, a comment.
        tokens = list(tokenize.generate_tokens(io.StringIO(script).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        # If it won't parse, it isn't valid Python and we can't safely take it apart.
        # So we check the raw text as-is. Being over-cautious is fine here, skipping the
        # check would not be.
        return script

    lines = script.splitlines()
    for token in tokens:
        if token.type != tokenize.COMMENT:   # only care about comments
            continue
        row = token.start[0] - 1             # tokens count lines from 1, lists from 0
        col = token.start[1]                 # where the "#" starts on that line
        if 0 <= row < len(lines):
            # A comment runs to the end of its line, so just chop the line there.
            lines[row] = lines[row][:col]
    return "\n".join(lines)


def _syntax_error(script):
    """Is this even valid Python? Give back a short note about the problem, or None if
    the code is fine.

    This matters more than it sounds. When the AI refuses a task it replies with a
    polite sentence, and that sentence lands in the "script" slot. Plain English has
    none of our banned patterns, so it used to sail through as approved, get uploaded,
    and die on the target with a confusing syntax error. Now we catch it here and can
    just say the model refused."""
    try:
        ast.parse(script)
    except SyntaxError as error:
        return f"line {error.lineno}: {error.msg}"
    except ValueError as error:
        # Rare, but source with null bytes raises this instead of SyntaxError.
        return str(error)
    return None                # parsed fine, so it really is Python


def validate(script):
    """Check one script and give back a verdict: approved or not, and why. Handing
    back the actual reasons, not just yes or no, lets us show the AI what it did wrong
    so it can try again."""
    issues = []        # anything in here means rejected
    warnings = []      # suspicious, but still allowed

    # An empty script can't run, so reject it right away and skip the rest.
    if not script or not script.strip():
        return {"approved": False, "issues": ["Empty script: nothing to run."], "warnings": []}

    # Make sure it's actually Python first. We note the problem but keep checking below
    # on purpose, so a reply that's both non-Python and full of dangerous commands
    # reports both facts.
    syntax_problem = _syntax_error(script)
    if syntax_problem:
        issues.append(
            f"not_python: the reply is not valid Python, which usually means the "
            f"model refused the task or its answer was cut off ({syntax_problem})."
        )

    # Only judge code that actually runs, a comment mentioning "sudo" isn't a real risk.
    code = _strip_comments(script)

    # Check against every banned pattern.
    for category, description, pattern in _BLOCKED:
        match = pattern.search(code)
        if match:
            # Quote exactly what matched, so a reader can see what tripped the rule.
            issues.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    # Same again, for the "suspicious but not blocking" list.
    for category, description, pattern in _WARNINGS:
        match = pattern.search(code)
        if match:
            warnings.append(f"{category}: script {description} (matched '{match.group(0).strip()}').")

    # Approved only if we found nothing to reject.
    return {"approved": not issues, "issues": issues, "warnings": warnings}


def validate_with_retries(generate, max_tries=DEFAULT_MAX_TRIES):
    """Ask the AI for a script, check it, and if it fails, ask again with feedback
    about what went wrong, up to a few times. `generate` is handed to us by the caller
    and does the actual talking to the AI, so this file never has to know about that."""
    attempt = None
    # A safe fallback verdict, in case `generate` ever hands back nothing usable.
    validation = {"approved": False, "issues": ["No attempt was generated."], "warnings": []}
    feedback = None        # empty on the first try, filled with the issues list on later ones

    for attempt_no in range(1, max_tries + 1):
        # Ask for one attempt. If nothing comes back, treat it as empty.
        attempt = generate(feedback) or {}
        # Dig out the script text, falling back to "" at every step so a half-formed
        # reply can never crash us.
        validation = validate(attempt.get("ai_response", {}).get("script", ""))
        if validation["approved"]:
            return _outcome(True, attempt_no, max_tries, attempt, validation)  # success, stop
        feedback = validation["issues"]        # failed, so remember why for the next prompt

    # Ran out of tries without ever getting an approved script.
    return _outcome(False, max_tries, max_tries, attempt, validation)


def _outcome(approved, attempts, max_tries, attempt, validation):
    """Wrap the result of the retry loop in one consistent dict, so main.py and
    report_writer always get the same fields back whether the run worked or not."""
    attempt = attempt or {}        # guard against a missing attempt before reading it
    return {
        "approved": approved,
        "completed": approved,     # another name for "did we end up with a usable script?"
        "attempts": attempts,      # which attempt number we stopped on
        "max_tries": max_tries,
        "validation": validation,  # the final verdict (issues/warnings) for the report
        "ai_response": attempt.get("ai_response", {}),
        "system_prompt": attempt.get("system_prompt", ""),
        "user_prompt": attempt.get("user_prompt", ""),
    }
