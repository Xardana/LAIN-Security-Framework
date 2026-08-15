"""
This file gathers the raw facts about a target machine using our own code, instead of
asking the AI to write a script that does it.

Why this file exists: we used to ask the AI to do two very different jobs at once,
decide what's worth checking AND write the code that digs the answer out of a command's
output. Turns out it's good at the first and bad at the second. Every wrong finding we
ever produced came from the second job:

  - it read `ss -tulpn`, grabbed column 3 (the connection backlog, not the port), and
    reported a hidden listener on port 1234 as "port 1"
  - it used a file check that follows shortcuts, so a disabled system file pointing at
    /dev/null got flagged as a dangerous world-writable file
  - it treated a command that FAILED as proof the firewall was strict
  - and since the AI writes fresh code every run, two runs of the same audit on the
    same machine disagreed with each other

None of those crashed. They all gave confident, tidy, wrong answers.

So now the split is: this file collects, the AI interprets. The commands here are fixed,
the parsing is ours, and the same machine gives the same answer every time. The AI still
decides what matters and explains it, which is the part it's good at.

Ground rules for anything added here:
1. Read-only. Every command only looks, never changes.
2. Never guess a column by its position. Match on the heading, or on the shape of the
   value, or use a command that removes the ambiguity.
3. If a command fails, say so. Never quietly turn a failure into a finding.
"""

import re      # [REQUIREMENT: Module] used to recognise the shape of values, e.g. "address:port".


# A listening socket looks like "0.0.0.0:22" or "[::]:22" or "127.0.0.53%lo:53". Instead
# of counting columns, we look for the piece with this shape. That's what makes it a
# port, rather than hoping it landed in a particular spot.
_ADDRESS_PORT = re.compile(r"^(?P<address>.+):(?P<port>\d+|\*)$")


# Plain facts about what's normal, so the AI has something to judge against. These are
# ON PURPOSE just labels, not verdicts. Our code doesn't decide "this is fine", it just
# tells the AI "this port is the standard SSH port" or "this binary ships with the OS"
# and lets the AI weigh it. This is what stops ordinary SSH being ranked scarier than a
# real backdoor: the backdoor sits on an unrecognised port that isn't in this map, so it
# still stands out.
WELL_KNOWN_PORTS = {
    22: "ssh", 25: "smtp", 53: "dns", 80: "http", 111: "rpcbind", 123: "ntp",
    143: "imap", 443: "https", 465: "smtps", 587: "smtp-submission", 631: "cups",
    993: "imaps", 995: "pop3s", 3306: "mysql", 5432: "postgresql", 6379: "redis",
    8080: "http-alt", 8443: "https-alt",
}

# The SUID binaries that ship as a normal part of Ubuntu. A SUID file NOT in this set is
# the interesting one, these are just the furniture. We match on the file name at the end
# of the path, since the directory can vary.
STANDARD_SUID = {
    "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "sg",
    "mount", "umount", "fusermount", "fusermount3", "pkexec", "ping", "ping6",
    "mount.nfs", "ntfs-3g", "chage", "expiry", "ssh-keysign", "unix_chkpwd",
    "dbus-daemon-launch-helper", "polkit-agent-helper-1", "snap-confine",
}


def _is_loopback(address):
    """Is this address the machine talking to itself only? A service bound to loopback
    (127.x or ::1) can't be reached from another machine, so it's much lower risk than
    the same service exposed on all interfaces."""
    bare = address.strip("[]").lower()
    return bare.startswith("127.") or bare == "::1" or "%lo" in address.lower()


# [REQUIREMENT: Classes] A Collector bundles the three things every check needs: the
# commands to run, the function that makes sense of what comes back, and a plain
# description for the report. Making it a class rather than three loose dicts means every
# collector is guaranteed to have all three parts, and they all get used the same way.
class Collector:
    def __init__(self, name, description, commands, parser):
        self.name = name                 # short id, e.g. "listening_ports"
        self.description = description    # what a person would call this check
        # `commands` is usually a plain {label: shell command} dict. But it can also be a
        # function that takes the depth tier and returns such a dict, which is how a check
        # makes itself lighter or heavier depending on the machine.
        self._commands = commands
        self.parser = parser              # function that turns raw output into records

    def commands_for(self, tier="detailed"):
        """The read-only commands to run at this depth. A fixed dict ignores the tier, a
        function gets to hand back a lighter or heavier set."""
        if callable(self._commands):
            return self._commands(tier)
        return self._commands

    @property
    def commands(self):
        """The default (full-depth) commands, kept so older callers that just read
        `.commands` still work."""
        return self.commands_for("detailed")

    def collect(self, outputs, tier="detailed"):
        """Turn the raw command output into a tidy result.

        `outputs` is what the target gave back: {label: {"stdout", "stderr",
        "exit_code"}}. We hand it to this collector's parser and wrap the result in a
        consistent shape, so every collector reports success and failure the same way and
        nothing downstream has to special-case anything."""
        records, errors = self.parser(outputs)
        return {
            "collector": self.name,
            "description": self.description,
            "commands": self.commands_for(tier),   # record what we actually ran at this depth
            "records": records,           # the facts we found
            "errors": errors,             # anything that went wrong, stated plainly
            # "ok" means we genuinely got to look. It is NOT the same as "found nothing",
            # and that difference is exactly what went wrong when a failed firewall
            # command got reported as a strict firewall.
            "ok": not errors,
        }


def _output(outputs, label):
    """Pull one command's result out of the bundle, with safe defaults so a missing
    entry can never crash a parser."""
    entry = outputs.get(label) or {}
    return (
        entry.get("stdout", "") or "",
        entry.get("stderr", "") or "",
        entry.get("exit_code", -1),
    )


def _failed(label, command, stderr, exit_code):
    """Build a consistent message for a command that didn't work, so the report can say
    "we couldn't check this" instead of inventing a result."""
    reason = stderr.strip().splitlines()[0] if stderr.strip() else f"exit code {exit_code}"
    return f"'{command}' failed ({reason})"


def _parse_listening_ports(outputs):
    """Work out which TCP ports the machine is listening on.

    We run `ss -ltnpH`. The -H drops the heading row, which kills the biggest source of
    confusion here: with headings present, adding or removing a flag shifts every column
    along, and any code counting positions quietly reads the wrong number. Even so, we
    don't trust position, we look for the field shaped like "address:port"."""
    records, errors = [], []
    stdout, stderr, exit_code = _output(outputs, "ss")

    if exit_code != 0:
        errors.append(_failed("ss", "ss -ltnpH", stderr, exit_code))
        return records, errors

    for line in stdout.splitlines():
        fields = line.split()
        if not fields:
            continue

        # Find the field that actually looks like an address and port. There are normally
        # two (the local end and the peer end), and the local one comes first.
        found = None
        for field in fields:
            match = _ADDRESS_PORT.match(field)
            if match and match.group("port") != "*":   # "*" is the peer wildcard, not a real port
                found = match
                break

        if not found:
            # Couldn't make sense of this line. We say so out loud rather than skipping
            # quietly, because a silent skip is how you end up confidently reporting that
            # a machine has no listeners when it has several.
            errors.append(f"could not read a port from: {line.strip()[:120]}")
            continue

        # The process column looks like: users:(("sshd",pid=812,fd=3))
        process = ""
        process_match = re.search(r'users:\(\("([^"]+)"', line)
        if process_match:
            process = process_match.group(1)

        address = found.group("address")
        port = int(found.group("port"))               # [REQUIREMENT: Casting] text -> number
        records.append({
            "port": port,
            "address": address,
            "process": process,                        # empty when we can't see it without root
            # Context for the AI to weigh, all computed by us so it's the same every run:
            # what this port usually is, and whether it's only reachable from the machine
            # itself.
            "well_known_service": WELL_KNOWN_PORTS.get(port, ""),
            "is_loopback": _is_loopback(address),
            "raw": line.strip(),                       # keep the original line as evidence
        })

    return records, errors


def _parse_local_accounts(outputs):
    """List the real user accounts and note which ones can become root.

    /etc/passwd is a fixed colon-separated format that hasn't changed in decades, so
    there's no column guessing to do here at all."""
    records, errors = [], []
    passwd_out, passwd_err, passwd_code = _output(outputs, "passwd")

    if passwd_code != 0:
        errors.append(_failed("passwd", "getent passwd", passwd_err, passwd_code))
        return records, errors

    # Work out who has admin rights first, so we can flag it per account below. A missing
    # sudo or wheel group is normal, not an error, plenty of systems have one and not the
    # other.
    admins = set()
    for label in ("sudo_group", "wheel_group", "admin_group"):
        group_out, _, group_code = _output(outputs, label)
        if group_code != 0:
            continue                                   # that group just doesn't exist here
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

        # A shell like /usr/sbin/nologin or /bin/false means the account exists for a
        # service and nobody can log in as it. That difference matters a lot, and it's the
        # kind of thing that gets lost when everything is reported the same way.
        can_login = not shell.strip().endswith(("nologin", "false", "/bin/sync"))

        # Real human accounts sit between 1000 and 60000. Below that is a service account,
        # and above it is one of the special built-ins like "nobody" (65534), which lives
        # deliberately above the range, not below it. So checking only for "under 1000"
        # quietly misclassifies it as a person.
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


def _is_only_permission_noise(stderr):
    """Decide whether a command's complaints are the boring, expected kind.

    `find` walks the filesystem as an ordinary user and grumbles every time it hits a
    folder it isn't allowed to open. That's completely normal, and it still makes `find`
    exit with a failure code. If we take that code at face value we announce that the
    check failed when it actually ran fine and just found nothing, which is the exact
    "found nothing" versus "wasn't allowed to look" confusion this whole file exists to
    prevent."""
    lines = [line for line in stderr.splitlines() if line.strip()]
    if not lines:
        return True                                # nothing complained about at all
    harmless = ("permission denied", "no such file or directory", "not a directory")
    return all(any(phrase in line.lower() for phrase in harmless) for line in lines)


def _permission_commands(tier):
    """How wide to cast the net when hunting for risky files, chosen by depth.

    On a low-resource machine we stick to the standard binary directories, which is quick
    and cheap. On a capable one we sweep the whole root filesystem. The "-xdev" keeps that
    sweep on the one filesystem, so it never wanders into mounted drives or network
    shares, and the wider search is what catches a SUID binary hiding somewhere unusual
    like /opt or a user's home."""
    if tier == "lightweight":
        return {
            "suid": "find /usr/bin /usr/sbin /bin /sbin -xdev -perm -4000 -type f",
            "world_writable": "find /etc /usr/bin /usr/sbin -xdev -perm -0002 -type f",
        }
    return {
        "suid": "find / -xdev -perm -4000 -type f",
        "world_writable": "find /etc /usr /opt /var /srv -xdev -perm -0002 -type f",
    }


def _parse_permissions(outputs):
    """Find files with the SUID bit set, and files anyone can write to.

    Note the "-type f" in both commands. It limits the search to real files, which is
    what quietly fixes the /dev/null problem: a disabled system service is a shortcut
    pointing at /dev/null, and /dev/null is a device, not a file, so it's now excluded at
    the source rather than flagged as a critical world-writable file."""
    records, errors = [], []

    for label, kind in (("suid", "suid"), ("world_writable", "world_writable")):
        stdout, stderr, exit_code = _output(outputs, label)
        # Only call it a real failure if the command complained about something we didn't
        # expect. An empty result with nothing but permission grumbles means the search
        # ran fine and found nothing, which is a perfectly good answer and shouldn't be
        # dressed up as an error.
        if exit_code != 0 and not _is_only_permission_noise(stderr):
            errors.append(_failed(label, f"find ({kind})", stderr, exit_code))
            continue
        for line in stdout.splitlines():
            path = line.strip()
            if not path:
                continue
            record = {"kind": kind, "path": path}
            if kind == "suid":
                # Flag the stock OS binaries so the AI can tell an ordinary SUID file
                # apart from an unexpected one that actually deserves a look.
                basename = path.rsplit("/", 1)[-1]
                record["is_standard"] = basename in STANDARD_SUID
            records.append(record)

    return records, errors


def _parse_firewall(outputs):
    """Report the firewall state, and be honest when we simply can't see it.

    This is the check that used to report "Restrictive Default iptables Policy" using, as
    its evidence, the error message from a command that had failed. Reading a firewall
    usually needs root and we run as an unprivileged user on purpose, so "we couldn't
    check" is the correct and expected answer here, not something to paper over."""
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
            # Ubuntu ships security updates from a channel with "security" in its name,
            # which is a far better signal than guessing from the package name.
            "is_security_update": "security" in source.lower(),
            "raw": line[:200],
        })

    return records, errors


# The list of everything we know how to collect. Every command here is read-only.
# "2>/dev/null" just hides noisy permission warnings from folders we're not allowed to
# open, which is normal when running as an ordinary user rather than root.
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
        # A function of the depth tier, not a fixed dict: the search widens on a capable
        # machine and stays light on a constrained one. We also deliberately do NOT hide
        # errors, so we can tell "nothing to find" from "find couldn't run".
        _permission_commands,
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
    """Hand back the collectors that suit this machine's OS. Right now only Linux is
    supported. Windows collectors are the next thing to add here, and keeping this behind
    one function means nothing else has to change when they land. This is the OS half of
    choosing what to run, the depth half is below."""
    if str(platform).lower().startswith("win"):
        return {}
    return LINUX_COLLECTORS


def _memory_gib(profile):
    """Read the machine's total memory out of the profile as a number of GiB, or None if
    we can't tell. The profile stores it as text like "3.8Gi total, ...", so we take the
    first value and convert whatever unit it carries."""
    text = str(profile.get("memory", "")).strip()
    if not text:
        return None
    token = text.split()[0]                            # e.g. "3.8Gi" or "512Mi"
    match = re.match(r"([\d.]+)\s*([KMGT]?)", token, re.IGNORECASE)
    if not match:
        return None
    try:
        value = float(match.group(1))                  # [REQUIREMENT: Casting]
    except ValueError:
        return None
    # How many of each unit make one GiB.
    per_gib = {"K": 1 / (1024 * 1024), "M": 1 / 1024, "G": 1, "T": 1024, "": 1}
    return value * per_gib.get(match.group(2).upper(), 1)


RESOURCE_TIER_MIN_GIB = 2.0    # below this much total RAM, keep the audit lightweight


def resource_tier(profile):
    """Decide how thorough to be from what the machine can comfortably handle. A small box
    gets a lighter audit so we don't hammer it, a capable one gets the full sweep. This
    reads ONLY the profile, so the same machine always gets the same decision, and
    changing the profile's memory figure changes the outcome."""
    gib = _memory_gib(profile)
    # If we couldn't read the memory at all, err on the side of gentle.
    if gib is None or gib < RESOURCE_TIER_MIN_GIB:
        return "lightweight"
    return "detailed"


def all_commands(collectors, tier="detailed"):
    """Flatten every collector's commands into one batch, so the whole audit runs over a
    single SSH connection instead of opening a new one per check. The tier is passed
    through so each check runs at the chosen depth. Labels are prefixed with the collector
    name to keep them apart."""
    commands = {}
    for name, collector in collectors.items():
        for label, command in collector.commands_for(tier).items():
            commands[f"{name}.{label}"] = command
    return commands


def collect_all(collectors, outputs, tier="detailed"):
    """Run every collector's parser over the command output and return one result per
    collector, keyed by name."""
    results = {}
    for name, collector in collectors.items():
        # Pull out just this collector's own outputs and strip the prefix back off.
        mine = {
            label.split(".", 1)[1]: value
            for label, value in outputs.items()
            if label.startswith(f"{name}.")
        }
        results[name] = collector.collect(mine, tier)
    return results
