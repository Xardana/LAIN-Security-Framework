"""
target_connector.py handles all the SSH communication with the remote target
machines. This program runs on a safe "controller" computer and never installs
anything on the target - it only connects in over SSH to (1) read information
and (2) run one approved script. Keeping every SSH detail in this one file
means the rest of the program can just say "collect_system_info" or
"execute_script" without needing to know anything about SSH itself.
"""

import uuid            # generates a random, one-of-a-kind id.
                       # We use it so each temporary script we upload gets a name that can never collide.

import paramiko        # [REQUIREMENT: Module] a library that speaks the SSH protocol for us,
                       # so we don't need to shell out to a separate `ssh` program.

"""This maps a short label to the shell command that produces it, for Linux.
Every command here is read-only. A couple of shell notes: "2>/dev/null" just
hides error messages, and "cmd_a || cmd_b" means "try cmd_a, and only run
cmd_b if cmd_a fails"."""
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

"""The same checks, rewritten for Windows. "2>nul" is the Windows equivalent
of hiding error messages. We need a separate list because Windows and Linux
show the same information through completely different commands."""
WINDOWS_COMMANDS = {
    "os": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",  # pipe the output through a filter
    "os_release": "ver",                                              # prints the Windows version
    "python_version": "python --version 2>&1 || python3 --version 2>&1",
    "cpu": "wmic cpu get Name,NumberOfCores /value",                 # CPU facts
    "memory": "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value",
    "arch": "echo %PROCESSOR_ARCHITECTURE%",                         # prints an environment variable
    "whoami": "whoami",
    "network": "ipconfig /all",                                      # full network configuration
    "tools": "for %t in (python python3 powershell) do where %t 2>nul",
    "packages": "python -m pip list 2>nul || pip list 2>nul",
}


def _connect(host, username, key_path=None, password=None):
    """Open one SSH connection to the target. Keeping this in a single helper
    means all our login rules live in one place. If no key or password is
    given, it just falls back to whatever the ssh-agent already knows -
    our own code never has to handle a secret directly."""
    client = paramiko.SSHClient()                          # create the SSH client
    # Read the local computer's list of known, trusted servers.
    client.load_system_host_keys()
    # If we've never seen this server before, just trust it automatically. (A future
    # version of this project plans to make this stricter and reject unknown servers.)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Actually connect and log in.
    client.connect(
        hostname=host,
        username=username,
        key_filename=key_path,                             # use this private key file if given
        password=password,                                 # or this password if given
        allow_agent=True,                                  # otherwise ask the running ssh-agent first
        look_for_keys=key_path is None,                    # only search ~/.ssh if no key was passed in
    )
    return client                                          # the caller is responsible for closing this


def _detect_platform(client):
    """Every other step depends on knowing the target's OS, so we check it
    once, right at the start."""
    # `uname` only exists on Unix-like systems, so if this prints anything, we know it's Unix.
    _, stdout, _ = client.exec_command("uname -s 2>/dev/null")
    # [REQUIREMENT: Casting] read the raw output, turn it into text, and trim extra whitespace.
    # A non-empty result means Unix; nothing at all means Windows.
    return "unix" if stdout.read().decode(errors="replace").strip() else "windows"


def _run_command_set(client, commands):
    """Run a whole {label: command} dict and give back a matching {label:
    output} dict. Reusing this one function for both operating systems avoids
    writing the same loop twice."""
    raw_data = {}                                          # the results we're building up
    for label, command in commands.items():
        _, stdout, _ = client.exec_command(command)        # run it; we only care about stdout
        raw_data[label] = stdout.read().decode(errors="replace").strip()  # [REQUIREMENT: Casting]
    return raw_data


def collect_system_info(host, username, key_path=None, password=None):
    """The public "read" step. This always closes the connection when it's
    done, even if something goes wrong partway through."""
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)                # "unix" or "windows"
        commands = UNIX_COMMANDS if platform == "unix" else WINDOWS_COMMANDS  # pick the matching command list
        raw_data = _run_command_set(client, commands)
        raw_data["platform"] = platform                    # note the OS so later steps don't have to re-check
        return raw_data
    finally:
        # This always runs, whether things succeeded or failed, so we never leave
        # a connection open by accident.
        client.close()


def execute_script(host, username, script, key_path=None, password=None):
    """The public "act" step. This uploads one already-approved script, runs
    it, captures whatever it prints, and then deletes it - leaving nothing
    behind on the target."""
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)
        if platform == "unix":
            # A random filename means two runs happening at the same time can never collide.
            remote_path = f"/tmp/.audit_{uuid.uuid4().hex}.py"
        else:
            # On Windows, we need to ask the shell for the temp folder path first, then build our own path.
            _, stdout, _ = client.exec_command("echo %TEMP%")
            temp_dir = stdout.read().decode(errors="replace").strip()
            remote_path = f"{temp_dir}\\audit_{uuid.uuid4().hex}.py"

        # Open a file-transfer channel over the same SSH connection.
        sftp = client.open_sftp()
        try:
            # Write the script's text to the target machine, and make sure the file gets
            # closed properly afterward no matter what happens.
            with sftp.open(remote_path, "w") as remote_file:  # "w" = open for writing
                remote_file.write(script)
        finally:
            sftp.close()                                      # close the file-transfer channel

        try:
            # Build the right "run it" and "clean up" commands for this OS.
            if platform == "unix":
                run_cmd = f"python3 {remote_path} || python {remote_path}"
                cleanup_cmd = f"rm -f {remote_path}"
            else:
                run_cmd = f"python {remote_path}"
                cleanup_cmd = f"del /f /q {remote_path}"

            # Keep both the normal output and any error messages.
            _, stdout, stderr = client.exec_command(run_cmd)
            # [REQUIREMENT: Casting] convert each stream of raw bytes into readable text.
            output = stdout.read().decode(errors="replace")   # the script's printed JSON
            errors = stderr.read().decode(errors="replace")   # any error/traceback text
        finally:
            # Always delete the temporary script, even if running it went wrong, so
            # nothing is left behind on the target.
            client.exec_command(cleanup_cmd)

        # Give back both streams; report_writer will read "output" as JSON.
        return {"output": output, "errors": errors}
    finally:
        client.close()
