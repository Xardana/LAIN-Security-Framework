# target_connector.py - owns ALL SSH communication with the remote targets.
# Architectural role: the framework runs on a safe "controller" machine and never
# installs anything on the target; it only reaches in over SSH to (1) read info and
# (2) run one approved script. Keeping every SSH detail in this one file means the
# rest of the program thinks in terms of "collect_system_info" / "execute_script",
# not sockets and channels.

import uuid            # stdlib. uuid.uuid4() generates a random 128-bit Universally Unique ID.
                       # We use it so each uploaded temp script gets a name that cannot collide.

import paramiko        # [REQUIREMENT: Module] third-party pure-Python SSHv2 client. It implements
                       # the SSH protocol (auth, encrypted channels, SFTP) so we don't shell out to `ssh`.

# A dict literal mapping a LABEL (the key) -> a shell COMMAND (the value) for Linux.
# WHY a dict: it pairs each result with a name and lets us loop over everything uniformly.
# Every command is read-only. Shell notes: "2>/dev/null" discards error output;
# "cmd_a || cmd_b" runs cmd_b only if cmd_a fails (exit code != 0).
UNIX_COMMANDS = {
    "os": "uname -a",                                              # kernel/OS summary line
    "os_release": "cat /etc/os-release 2>/dev/null",              # distro name + version
    "python_version": "python3 --version 2>/dev/null || python --version 2>/dev/null",
    "cpu": "lscpu 2>/dev/null || cat /proc/cpuinfo 2>/dev/null",  # CPU model/cores
    "memory": "free -h 2>/dev/null",                             # RAM, human-readable units
    "arch": "uname -m",                                          # architecture, e.g. x86_64
    "whoami": "whoami",                                          # current username
    "network": "ip addr 2>/dev/null || ifconfig 2>/dev/null",   # network interfaces
    "tools": "for t in python3 python powershell bash ip ifconfig; do command -v $t; done",
    "packages": "python3 -m pip list 2>/dev/null || pip3 list 2>/dev/null || pip list 2>/dev/null",
}

# The same logical checks rewritten for Windows (cmd.exe). "2>nul" is the Windows
# equivalent of discarding error output. WHY a separate dict: the two operating
# systems expose the same facts through completely different commands.
WINDOWS_COMMANDS = {
    "os": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",  # "|" pipes output into findstr (a filter)
    "os_release": "ver",                                              # prints the Windows version
    "python_version": "python --version 2>&1 || python3 --version 2>&1",
    "cpu": "wmic cpu get Name,NumberOfCores /value",                 # WMI query for CPU facts
    "memory": "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value",
    "arch": "echo %PROCESSOR_ARCHITECTURE%",                         # echoes an environment variable
    "whoami": "whoami",
    "network": "ipconfig /all",                                      # full network configuration
    "tools": "for %t in (python python3 powershell) do where %t 2>nul",
    "packages": "python -m pip list 2>nul || pip list 2>nul",
}


def _connect(host, username, key_path=None, password=None):
    # WHY (logic): one private helper builds every connection so auth policy lives in a
    # single place. key_path/password default to None, meaning "not supplied" - in which
    # case authentication falls back to the ssh-agent (no secret is handled by our code).
    client = paramiko.SSHClient()                          # create the SSH client object
    # load_system_host_keys() reads the OS known_hosts file so we recognise servers
    # we've connected to before (this is the SSH defence against man-in-the-middle).
    client.load_system_host_keys()
    # If the host key is unknown, this policy auto-accepts it. (Phase 3 plans to tighten
    # this to reject unknown keys.) set_missing_host_key_policy installs that decision rule.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # .connect() performs the TCP connect + SSH handshake + authentication. Passing
    # arguments BY KEYWORD (name=value) makes the call self-documenting and order-independent.
    client.connect(
        hostname=host,
        username=username,
        key_filename=key_path,                             # use this private key file if given
        password=password,                                 # or this password if given
        allow_agent=True,                                  # else ask the running ssh-agent (agent-first)
        look_for_keys=key_path is None,                    # only auto-scan ~/.ssh when no key was passed
    )
    return client                                          # the CALLER must close it (see try/finally below)


def _detect_platform(client):
    # WHY (logic): every other step depends on knowing the OS, so we probe it once.
    # client.exec_command(cmd) runs a command on the target and returns a 3-TUPLE of
    # file-like channel objects: (stdin, stdout, stderr). We "unpack" that tuple; the
    # underscores `_` are throwaway names for the streams we don't need here.
    _, stdout, _ = client.exec_command("uname -s 2>/dev/null")  # `uname` exists only on Unix
    # CHAIN of calls, evaluated left to right:
    #   stdout.read()           -> reads all output as raw BYTES (e.g. b"Linux\n")
    #   .decode(errors="replace") -> [REQUIREMENT: Casting] converts bytes to a str using UTF-8;
    #                                "replace" swaps any undecodable byte for the U+FFFD char
    #                                instead of raising, so this never crashes.
    #   .strip()                -> removes surrounding whitespace/newlines
    # A non-empty string is "truthy" -> Unix; an empty string is "falsy" -> Windows.
    return "unix" if stdout.read().decode(errors="replace").strip() else "windows"


def _run_command_set(client, commands):
    # WHY (logic): generic runner - hand it any {label: command} dict and it returns
    # {label: output}. Reusing it for both OS dicts avoids duplicated loops.
    raw_data = {}                                          # start an empty result dict
    # .items() yields (key, value) pairs from the dict; the `for label, command in`
    # unpacks each pair into two named variables on every iteration.
    for label, command in commands.items():
        _, stdout, _ = client.exec_command(command)        # run it; keep only stdout
        # [REQUIREMENT: Casting] bytes -> str -> trimmed, then stored under its label.
        raw_data[label] = stdout.read().decode(errors="replace").strip()
    return raw_data


def collect_system_info(host, username, key_path=None, password=None):
    # WHY (logic): the public "READ" step. It guarantees the connection is always closed,
    # even if something fails midway, by using try/finally.
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)                # "unix" or "windows"
        # Ternary chooses the command set matching the detected OS.
        commands = UNIX_COMMANDS if platform == "unix" else WINDOWS_COMMANDS
        raw_data = _run_command_set(client, commands)
        raw_data["platform"] = platform                    # tag the result so later steps know the OS
        return raw_data
    finally:
        # `finally` ALWAYS runs - whether the try block returned normally or raised an
        # exception. WHY: an unclosed SSH session leaks a socket/file handle on both ends.
        client.close()


def execute_script(host, username, script, key_path=None, password=None):
    # WHY (logic): the public "ACT" step. It uploads ONE validated script, runs it,
    # captures its output, and deletes it - leaving no trace on the target.
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)
        if platform == "unix":
            # f-string (formatted string literal): the f prefix lets {expression} be
            # evaluated and inserted. uuid.uuid4().hex is a 32-char random hex string,
            # so two concurrent runs can never pick the same temp filename.
            remote_path = f"/tmp/.audit_{uuid.uuid4().hex}.py"
        else:
            # On Windows, SFTP does NOT expand %TEMP%, so we ask the shell to print it first,
            # then build the path ourselves. "\\" in a normal string is a single backslash.
            _, stdout, _ = client.exec_command("echo %TEMP%")
            temp_dir = stdout.read().decode(errors="replace").strip()
            remote_path = f"{temp_dir}\\audit_{uuid.uuid4().hex}.py"

        # open_sftp() opens a file-transfer channel over the existing SSH connection.
        sftp = client.open_sftp()
        try:
            # `with` is a CONTEXT MANAGER: it calls the file's __enter__ on entry and
            # GUARANTEES __exit__ (which closes the remote file) on exit, even on error.
            # WHY: it's the idiomatic, leak-proof way to handle files in Python.
            with sftp.open(remote_path, "w") as remote_file:  # "w" = open for writing (truncate)
                remote_file.write(script)                     # write the script's source text
        finally:
            sftp.close()                                      # close the SFTP channel

        try:
            # Build OS-appropriate "run" and "cleanup" commands as strings.
            if platform == "unix":
                run_cmd = f"python3 {remote_path} || python {remote_path}"
                cleanup_cmd = f"rm -f {remote_path}"
            else:
                run_cmd = f"python {remote_path}"
                cleanup_cmd = f"del /f /q {remote_path}"

            # Here we keep BOTH stdout and stderr to capture findings and any errors.
            _, stdout, stderr = client.exec_command(run_cmd)
            # [REQUIREMENT: Casting] decode each byte stream to text.
            output = stdout.read().decode(errors="replace")   # the script's printed JSON
            errors = stderr.read().decode(errors="replace")   # any error/traceback text
        finally:
            # Always delete the temp script, even if running it raised - no residue left behind.
            client.exec_command(cleanup_cmd)

        # Return both streams in a dict; report_writer will parse "output" as JSON.
        return {"output": output, "errors": errors}
    finally:
        client.close()
