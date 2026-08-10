"""
collectors.py gathers the raw facts about a target machine using our own code,
instead of asking the AI to write a script that does it.

Why this file exists
--------------------
Up to now we asked the AI to do two very different jobs at once: decide what is
worth checking, AND write the code that digs the answer out of a command's
output. It turns out it's good at the first and bad at the second. Every wrong
finding we produced came from the second job:

  * it read `ss -tulpn` and grabbed column 3, which is the connection backlog,
    not the port - so a hidden listener on port 1234 was reported as "port 1"
  * it used a file check that follows shortcuts, so a disabled system file that
    points at /dev/null got reported as a dangerous world-writable file
  * it treated a command that FAILED as evidence the firewall was strict
  * and because the AI writes fresh code every run, two runs of the same audit
    on the same machine disagreed with each other

None of those crashed. They all produced confident, tidy, wrong answers.

So the split is now: this file collects, the AI interprets. The commands here
are fixed, the parsing is ours, and the same machine gives the same answer
every time. The AI still decides what matters and explains it, which is the
part it's actually good at.

Ground rules for anything added here
------------------------------------
1. Read-only. Every command must only look, never change.
2. Never guess a column by its position. Match on the column heading, or on
   the shape of the value, or use a command that removes the ambiguity.
3. If a command fails, say so. Never quietly turn a failure into a finding.
"""

import re      # [REQUIREMENT: Module] used to recognise the shape of values, e.g. "address:port".


"""A listening socket line looks like "0.0.0.0:22" or "[::]:22" or
"127.0.0.53%lo:53". Rather than counting columns, we look for the piece that
actually has this shape, which is what makes it a port instead of hoping it
landed in a particular position."""
_ADDRESS_PORT = re.compile(r"^(?P<address>.+):(?P<port>\d+|\*)$")


"""[REQUIREMENT: Classes] A Collector bundles together the three things every
check needs: the commands to run on the target, the function that makes sense
of what came back, and a plain-English description for the report. Making this
a class rather than three loose dictionaries means every collector is
guaranteed to have all three parts, and they can all be used the same way."""
class Collector:
    def __init__(self, name, description, commands, parser):
        self.name = name                 # short id, e.g. "listening_ports"
        self.description = description    # what a human would call this check
        self.commands = commands          # {label: shell command} - all read-only
        self.parser = parser              # function that turns raw output into records

    def collect(self, outputs):
        """Turn the raw command output into a tidy result.

        `outputs` is what the target gave us back: {label: {"stdout", "stderr",
        "exit_code"}}. We hand that to this collector's parser and wrap the
        result in a consistent shape, so every collector reports success and
        failure the same way and nothing downstream has to special-case."""
        records, errors = self.parser(outputs)
        return {
            "collector": self.name,
            "description": self.description,
            "commands": self.commands,
            "records": records,           # the actual facts we found
            "errors": errors,             # anything that went wrong, stated plainly
            # "ok" means we genuinely managed to look. It is NOT the same as
            # "found nothing" - that distinction is exactly what went wrong when
            # a failed firewall command got reported as a strict firewall.
            "ok": not errors,
        }


def _output(outputs, label):
    """Pull one command's result out of the bundle, with safe defaults so a
    missing entry can never crash a parser."""
    entry = outputs.get(label) or {}
    return (
        entry.get("stdout", "") or "",
        entry.get("stderr", "") or "",
        entry.get("exit_code", -1),
    )


def _failed(label, command, stderr, exit_code):
    """Build a consistent message for a command that didn't work, so the report
    can say "we could not check this" instead of inventing a result."""
    reason = stderr.strip().splitlines()[0] if stderr.strip() else f"exit code {exit_code}"
    return f"'{command}' failed ({reason})"


# --------------------------------------------------------------------------
# Listening ports
# --------------------------------------------------------------------------

def _parse_listening_ports(outputs):
    """Work out which TCP ports the machine is listening on.

    We run `ss -ltnpH`. The -H switch drops the heading row, which removes the
    single biggest source of confusion here: with headings present, adding or
    removing a flag shifts every column along and any code counting positions
    silently reads the wrong number. Even so, we don't trust position - we look
    for the field shaped like "address:port"."""
    records, errors = [], []
    stdout, stderr, exit_code = _output(outputs, "ss")

    if exit_code != 0:
        errors.append(_failed("ss", "ss -ltnpH", stderr, exit_code))
        return records, errors

    for line in stdout.splitlines():
        fields = line.split()
        if not fields:
            continue

        """Find the field that actually looks like an address and port. There are
        normally two (the local end and the peer end); the local one comes first."""
        found = None
        for field in fields:
            match = _ADDRESS_PORT.match(field)
            if match and match.group("port") != "*":   # "*" is the peer wildcard, not a real port
                found = match
                break

        if not found:
            """We could not make sense of this line. We say so out loud rather than
            skipping quietly, because a silent skip is how you end up confidently
            reporting that a machine has no listeners when it has several."""
            errors.append(f"could not read a port from: {line.strip()[:120]}")
            continue

        # The process column looks like: users:(("sshd",pid=812,fd=3))
        process = ""
        process_match = re.search(r'users:\(\("([^"]+)"', line)
        if process_match:
            process = process_match.group(1)

        records.append({
            "port": int(found.group("port")),          # [REQUIREMENT: Casting] text -> number
            "address": found.group("address"),
            "process": process,                        # empty when we lack permission to see it
            "raw": line.strip(),                       # keep the original line as evidence
        })

    return records, errors


# --------------------------------------------------------------------------
# Local accounts
# --------------------------------------------------------------------------

def _parse_local_accounts(outputs):
    """List the real user accounts and note which ones can become root.

    /etc/passwd is a fixed, colon-separated format that has not changed in
    decades, so there is no column guessing to do here at all."""
    records, errors = [], []
    passwd_out, passwd_err, passwd_code = _output(outputs, "passwd")

    if passwd_code != 0:
        errors.append(_failed("passwd", "getent passwd", passwd_err, passwd_code))
        return records, errors

    """Work out who has admin rights first, so we can flag it per account below.
    A missing sudo or wheel group is normal, not an error - plenty of systems
    have one and not the other."""
    admins = set()
    for label in ("sudo_group", "wheel_group", "admin_group"):
        group_out, _, group_code = _output(outputs, label)
        if group_code != 0:
            continue                                   # that group simply doesn't exist here
        for line in group_out.splitlines():
            # Format: name:x:gid:member1,member2
            parts = line.split(":")
            if len(parts) >= 4 and parts[3].strip():
                admins.update(m.strip() for m in parts[3].split(",") if m.strip())

    for line in passwd_out.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue                                   # not a real passwd entry
        name, _, uid_text, _, _, home, shell = parts[:7]
        try:
            uid = int(uid_text)                        # [REQUIREMENT: Casting]
        except ValueError:
            errors.append(f"could not read the user id on line: {line.strip()[:120]}")
            continue

        """A shell like /usr/sbin/nologin or /bin/false means the account exists for
        a service and nobody can log into it. That distinction matters a lot and is
        the sort of thing that gets lost when everything is reported the same way."""
        can_login = not shell.strip().endswith(("nologin", "false", "/bin/sync"))

        """Real human accounts sit between 1000 and 60000. Anything below that is a
        service account, and anything above it is one of the special built-ins like
        "nobody" (65534), which lives deliberately above the range rather than below
        it - so checking only for "under 1000" quietly misclassifies it as a person."""
        is_system_account = uid < 1000 or uid > 60000

        records.append({
            "name": name,
            "uid": uid,
            "is_root": uid == 0,
            "is_system_account": is_system_account,
            "can_login": can_login,
            "has_admin_rights": name in admins,
            "shell": shell,
            "home": home,
        })

    return records, errors


# --------------------------------------------------------------------------
# File permissions
# --------------------------------------------------------------------------

def _parse_permissions(outputs):
    """Find files with the SUID bit set, and files anyone can write to.

    Note the "-type f" in both commands. That restricts the search to real
    files, which is what quietly fixes the /dev/null problem: a disabled system
    service is a shortcut pointing at /dev/null, and /dev/null is a device, not
    a file, so it is now excluded at the source rather than being flagged as a
    critical world-writable file."""
    records, errors = [], []

    for label, kind in (("suid", "suid"), ("world_writable", "world_writable")):
        stdout, stderr, exit_code = _output(outputs, label)
        """`find` returns a non-zero code just for hitting folders it can't read,
        which is completely normal as a non-root user. So we only treat it as a
        real failure if it also gave us nothing at all."""
        if exit_code != 0 and not stdout.strip():
            errors.append(_failed(label, f"find ({kind})", stderr, exit_code))
            continue
        for line in stdout.splitlines():
            path = line.strip()
            if path:
                records.append({"kind": kind, "path": path})

    return records, errors


# --------------------------------------------------------------------------
# Firewall
# --------------------------------------------------------------------------

def _parse_firewall(outputs):
    """Report the firewall state, and be honest when we simply can't see it.

    This is the check that previously reported "Restrictive Default iptables
    Policy" using, as its evidence, the error message from a command that had
    failed. Reading a firewall usually needs root and we deliberately run as an
    unprivileged user, so "we could not check" is the correct and expected
    answer here - not something to paper over."""
    records, errors = [], []
    checked_anything = False

    ufw_out, ufw_err, ufw_code = _output(outputs, "ufw")
    if ufw_code == 0 and ufw_out.strip():
        checked_anything = True
        first = ufw_out.strip().splitlines()[0]
        records.append({
            "tool": "ufw",
            "state": "active" if "active" in first.lower() else "inactive",
            "raw": first.strip(),
        })
    elif ufw_out.strip() or ufw_err.strip():
        errors.append(_failed("ufw", "ufw status", ufw_err, ufw_code))

    nft_out, nft_err, nft_code = _output(outputs, "nft")
    if nft_code == 0 and nft_out.strip():
        checked_anything = True
        # Counting rule lines is a rough but honest summary of "is anything configured".
        rule_count = sum(1 for line in nft_out.splitlines() if line.strip().startswith("rule"))
        records.append({"tool": "nftables", "state": "readable", "rule_count": rule_count})
    elif nft_err.strip():
        errors.append(_failed("nft", "nft list ruleset", nft_err, nft_code))

    if not checked_anything and not errors:
        errors.append("no firewall tool could be read (this usually needs root)")

    return records, errors


# --------------------------------------------------------------------------
# Enabled services
# --------------------------------------------------------------------------

def _parse_services(outputs):
    """List the services set to start automatically at boot."""
    records, errors = [], []
    stdout, stderr, exit_code = _output(outputs, "enabled")

    if exit_code != 0:
        errors.append(_failed("enabled", "systemctl list-unit-files --state=enabled", stderr, exit_code))
        return records, errors

    for line in stdout.splitlines():
        fields = line.split()
        # Each line reads: <unit name> <state> [preset]
        if len(fields) >= 2 and fields[0].endswith((".service", ".socket", ".timer", ".target")):
            records.append({"unit": fields[0], "state": fields[1]})

    return records, errors


# --------------------------------------------------------------------------
# Pending updates
# --------------------------------------------------------------------------

def _parse_updates(outputs):
    """List packages with an update waiting, and flag the security ones."""
    records, errors = [], []
    stdout, stderr, exit_code = _output(outputs, "upgradable")

    if exit_code != 0:
        errors.append(_failed("upgradable", "apt list --upgradable", stderr, exit_code))
        return records, errors

    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Listing"):     # skip apt's own header line
            continue
        # Each line reads: name/source version arch [upgradable from: old]
        name, separator, remainder = line.partition("/")
        if not separator:
            continue
        source = remainder.split()[0] if remainder.split() else ""
        records.append({
            "package": name,
            "source": source,
            # Ubuntu publishes security updates from a channel with "security" in
            # its name, which is a far better signal than guessing from the name.
            "is_security_update": "security" in source.lower(),
            "raw": line[:200],
        })

    return records, errors


# --------------------------------------------------------------------------
# The registry of everything we know how to collect
# --------------------------------------------------------------------------

"""Every command below is read-only. "2>/dev/null" just hides noisy permission
warnings from folders we're not allowed to look in, which is normal and expected
when running as an ordinary user rather than as root."""
LINUX_COLLECTORS = {
    "listening_ports": Collector(
        "listening_ports", "TCP ports the machine is listening on",
        {"ss": "ss -ltnpH"},
        _parse_listening_ports,
    ),
    "local_accounts": Collector(
        "local_accounts", "Local user accounts and who has admin rights",
        {
            "passwd": "getent passwd",
            "sudo_group": "getent group sudo",
            "wheel_group": "getent group wheel",
            "admin_group": "getent group admin",
        },
        _parse_local_accounts,
    ),
    "weak_permissions": Collector(
        "weak_permissions", "Files with the SUID bit set, and world-writable files",
        {
            "suid": "find /usr/bin /usr/sbin /bin /sbin -xdev -perm -4000 -type f 2>/dev/null",
            "world_writable": "find /etc /usr/bin /usr/sbin -xdev -perm -0002 -type f 2>/dev/null",
        },
        _parse_permissions,
    ),
    "firewall_status": Collector(
        "firewall_status", "Host firewall state",
        {"ufw": "ufw status 2>/dev/null", "nft": "nft list ruleset 2>/dev/null"},
        _parse_firewall,
    ),
    "running_services": Collector(
        "running_services", "Services set to start automatically",
        {"enabled": "systemctl list-unit-files --state=enabled --no-pager --no-legend"},
        _parse_services,
    ),
    "patch_status": Collector(
        "patch_status", "Packages with a pending update",
        {"upgradable": "apt list --upgradable 2>/dev/null"},
        _parse_updates,
    ),
}


def for_platform(platform):
    """Give back the collectors that suit this machine. Right now only Linux is
    supported; Windows collectors are the next thing to add here, and keeping
    this behind one function means nothing else has to change when they land."""
    if str(platform).lower().startswith("win"):
        return {}
    return LINUX_COLLECTORS


def all_commands(collectors):
    """Flatten every collector's commands into one batch, so the whole audit can
    run over a single SSH connection instead of opening a new one per check.
    Labels are prefixed with the collector name to keep them apart."""
    commands = {}
    for name, collector in collectors.items():
        for label, command in collector.commands.items():
            commands[f"{name}.{label}"] = command
    return commands


def collect_all(collectors, outputs):
    """Run every collector's parser over the command output and return one
    result per collector, keyed by name."""
    results = {}
    for name, collector in collectors.items():
        # Pull out just this collector's own outputs and strip the prefix back off.
        mine = {
            label.split(".", 1)[1]: value
            for label, value in outputs.items()
            if label.startswith(f"{name}.")
        }
        results[name] = collector.collect(mine)
    return results
