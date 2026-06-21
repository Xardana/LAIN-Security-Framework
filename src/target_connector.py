"""
target_connector.py
===================
Single responsibility: all SSH communication with the remote target machines.
No prompt building, validation, or report writing happens here.

Auth is "agent-first": paramiko asks the running ssh-agent (or Pageant on
Windows) to authenticate, so no private key material or passwords ever have to
be read, stored, or shipped with this program - even when it is packaged into a
standalone exe/elf. The --key / SSH_PASSWORD options remain as optional
fallbacks for machines that have neither an agent-loaded key nor agent access.

A target may be Linux or Windows (OpenSSH server on cmd.exe), so the read-only
enumeration runs whichever command set matches the detected remote platform.

Coding requirements demonstrated in THIS file:
    * Functions - the connect / detect / collect / execute steps are all defs.
    * Modules   - standard-library `uuid` (unique temp filenames) and the
                  third-party `paramiko` SSH library.
    * Casting   - raw command output arrives as bytes and is converted to str
                  with .decode(...) before the rest of the program uses it.
"""

import uuid                # standard library: build a unique temporary script name

import paramiko            # third-party: the SSH client that does the real work

# Read-only enumeration commands for a Linux/Unix target. The dict KEY is the
# label stored in the result; the VALUE is the shell command that produces it.
UNIX_COMMANDS = {
    "os": "uname -a",
    "os_release": "cat /etc/os-release 2>/dev/null",
    "python_version": "python3 --version 2>/dev/null || python --version 2>/dev/null",
    "cpu": "lscpu 2>/dev/null || cat /proc/cpuinfo 2>/dev/null",
    "memory": "free -h 2>/dev/null",
    "arch": "uname -m",
    "whoami": "whoami",
    "network": "ip addr 2>/dev/null || ifconfig 2>/dev/null",
    "tools": "for t in python3 python powershell bash ip ifconfig; do command -v $t; done",
    "packages": "python3 -m pip list 2>/dev/null || pip3 list 2>/dev/null || pip list 2>/dev/null",
}

# The same set of read-only checks, expressed in Windows (cmd.exe) syntax.
WINDOWS_COMMANDS = {
    "os": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
    "os_release": "ver",
    "python_version": "python --version 2>&1 || python3 --version 2>&1",
    "cpu": "wmic cpu get Name,NumberOfCores /value",
    "memory": "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value",
    "arch": "echo %PROCESSOR_ARCHITECTURE%",
    "whoami": "whoami",
    "network": "ipconfig /all",
    "tools": "for %t in (python python3 powershell) do where %t 2>nul",
    "packages": "python -m pip list 2>nul || pip list 2>nul",
}


def _connect(host, username, key_path=None, password=None):
    """Open and return an authenticated SSH connection to one target.

    allow_agent=True is what makes auth agent-first; look_for_keys is only
    enabled when no explicit key path was supplied. The caller is responsible
    for closing the returned client.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=username,
        key_filename=key_path,
        password=password,
        allow_agent=True,
        look_for_keys=key_path is None,
    )
    return client


def _detect_platform(client):
    """Return "unix" or "windows" for an already-open connection.

    We run a Unix-only probe (`uname -s`): if it prints something the target is
    Unix-like; if it prints nothing the target is Windows. This is what lets the
    rest of the file pick the correct command set.
    """
    _, stdout, _ = client.exec_command("uname -s 2>/dev/null")
    # [REQUIREMENT: Casting] stdout is a byte stream; .decode(...) casts the
    # raw bytes into a str so we can call .strip() and compare it as text.
    return "unix" if stdout.read().decode(errors="replace").strip() else "windows"


def _run_command_set(client, commands):
    """Run every command in a {label: command} dict and collect the output.

    Returns a new dict of {label: text-output}. Each command's byte output is
    decoded to a str (casting) and trimmed before being stored.
    """
    raw_data = {}
    for label, command in commands.items():
        _, stdout, _ = client.exec_command(command)
        # [REQUIREMENT: Casting] bytes -> str via .decode before storing.
        raw_data[label] = stdout.read().decode(errors="replace").strip()
    return raw_data


def collect_system_info(host, username, key_path=None, password=None):
    """Top-level "read" step: SSH in, enumerate the target, return raw output.

    Opens a connection, detects the platform, runs the matching read-only
    command set, tags the result with the platform, and always closes the
    connection (the finally block) before returning the raw dict that
    system_profile.py will later parse.
    """
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)
        commands = UNIX_COMMANDS if platform == "unix" else WINDOWS_COMMANDS
        raw_data = _run_command_set(client, commands)
        raw_data["platform"] = platform
        return raw_data
    finally:
        client.close()


def execute_script(host, username, script, key_path=None, password=None):
    """Top-level "act" step: run one validator-approved script on the target.

    Transfers the script to a unique temporary path, runs it, captures stdout
    and stderr, then deletes the temporary copy - again always closing the
    connection afterwards. Returns {"output": ..., "errors": ...}.
    """
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)
        if platform == "unix":
            # uuid gives a unique filename so concurrent runs never clash.
            remote_path = f"/tmp/.audit_{uuid.uuid4().hex}.py"
        else:
            # SFTP paths are not shell-expanded, so resolve %TEMP% ourselves first.
            _, stdout, _ = client.exec_command("echo %TEMP%")
            temp_dir = stdout.read().decode(errors="replace").strip()
            remote_path = f"{temp_dir}\\audit_{uuid.uuid4().hex}.py"

        # Send the script to the target over SFTP (remote file handling).
        sftp = client.open_sftp()
        try:
            with sftp.open(remote_path, "w") as remote_file:
                remote_file.write(script)
        finally:
            sftp.close()

        try:
            # Build OS-appropriate "run" and "clean up" commands.
            if platform == "unix":
                run_cmd = f"python3 {remote_path} || python {remote_path}"
                cleanup_cmd = f"rm -f {remote_path}"
            else:
                run_cmd = f"python {remote_path}"
                cleanup_cmd = f"del /f /q {remote_path}"

            _, stdout, stderr = client.exec_command(run_cmd)
            # [REQUIREMENT: Casting] decode both byte streams into text.
            output = stdout.read().decode(errors="replace")
            errors = stderr.read().decode(errors="replace")
        finally:
            # Always remove the temporary script, even if running it failed.
            client.exec_command(cleanup_cmd)

        return {"output": output, "errors": errors}
    finally:
        client.close()
