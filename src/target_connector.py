"""Handles all SSH communication with remote target machines. No prompt
building, validation, or report writing belongs here.

Auth is agent-first: paramiko asks the running ssh-agent (or Pageant on
Windows) to authenticate, so no private key material or passwords ever
have to be read, stored, or shipped with this program - including when
it's packaged into a standalone exe/elf. --key / SSH_PASSWORD remain as
optional fallbacks for machines that have neither an agent-loaded key nor
agent access.

Targets may be Linux or Windows (OpenSSH server on cmd.exe), so enumeration
runs against whichever command set matches the detected remote platform.
"""

import uuid

import paramiko

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
}

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
}


def _connect(host, username, key_path=None, password=None):
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
    """Returns "windows" or "unix" based on whether the remote shell
    understands a Unix-only probe command."""
    _, stdout, _ = client.exec_command("uname -s 2>/dev/null")
    return "unix" if stdout.read().decode(errors="replace").strip() else "windows"


def _run_command_set(client, commands):
    raw_data = {}
    for label, command in commands.items():
        _, stdout, _ = client.exec_command(command)
        raw_data[label] = stdout.read().decode(errors="replace").strip()
    return raw_data


def collect_system_info(host, username, key_path=None, password=None):
    """SSH into the target, run read-only enumeration commands for the
    detected platform, and return the raw output for system_profile.py."""
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
    """Transfer a validator-approved script to the target, execute it, capture
    its output, and remove the temporary copy before closing the connection."""
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)
        if platform == "unix":
            remote_path = f"/tmp/.audit_{uuid.uuid4().hex}.py"
        else:
            # SFTP paths aren't shell-expanded, so resolve %TEMP% first.
            _, stdout, _ = client.exec_command("echo %TEMP%")
            temp_dir = stdout.read().decode(errors="replace").strip()
            remote_path = f"{temp_dir}\\audit_{uuid.uuid4().hex}.py"

        sftp = client.open_sftp()
        try:
            with sftp.open(remote_path, "w") as remote_file:
                remote_file.write(script)
        finally:
            sftp.close()

        try:
            if platform == "unix":
                run_cmd = f"python3 {remote_path} || python {remote_path}"
                cleanup_cmd = f"rm -f {remote_path}"
            else:
                run_cmd = f"python {remote_path}"
                cleanup_cmd = f"del /f /q {remote_path}"

            _, stdout, stderr = client.exec_command(run_cmd)
            output = stdout.read().decode(errors="replace")
            errors = stderr.read().decode(errors="replace")
        finally:
            client.exec_command(cleanup_cmd)

        return {"output": output, "errors": errors}
    finally:
        client.close()
