# target_connector.py - all SSH communication with the remote target machines.
# It collects read-only system info, and later runs a validated script there.

import uuid            # uuid.uuid4() makes a random unique id (for unique temp filenames)

import paramiko        # [REQUIREMENT: Module] third-party SSH library that does the connecting

# A dict mapping a LABEL -> the shell COMMAND that produces that piece of info,
# for Linux/Unix targets. All commands are read-only (they only look, never change).
# "2>/dev/null" hides errors; "a || b" runs b only if a fails.
UNIX_COMMANDS = {
    "os": "uname -a",                                              # kernel / OS line
    "os_release": "cat /etc/os-release 2>/dev/null",              # distro name/version
    "python_version": "python3 --version 2>/dev/null || python --version 2>/dev/null",
    "cpu": "lscpu 2>/dev/null || cat /proc/cpuinfo 2>/dev/null",  # CPU details
    "memory": "free -h 2>/dev/null",                             # RAM usage, human units
    "arch": "uname -m",                                          # machine architecture (x86_64...)
    "whoami": "whoami",                                          # current user name
    "network": "ip addr 2>/dev/null || ifconfig 2>/dev/null",   # network interfaces
    "tools": "for t in python3 python powershell bash ip ifconfig; do command -v $t; done",
    "packages": "python3 -m pip list 2>/dev/null || pip3 list 2>/dev/null || pip list 2>/dev/null",
}

# The same set of read-only checks written in Windows (cmd.exe) syntax.
# "2>nul" is the Windows way to hide errors.
WINDOWS_COMMANDS = {
    "os": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",  # filter systeminfo lines
    "os_release": "ver",                                              # Windows version string
    "python_version": "python --version 2>&1 || python3 --version 2>&1",
    "cpu": "wmic cpu get Name,NumberOfCores /value",                 # CPU name + core count
    "memory": "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value",
    "arch": "echo %PROCESSOR_ARCHITECTURE%",                         # echo an env variable
    "whoami": "whoami",
    "network": "ipconfig /all",                                      # full network config
    "tools": "for %t in (python python3 powershell) do where %t 2>nul",
    "packages": "python -m pip list 2>nul || pip list 2>nul",
}


def _connect(host, username, key_path=None, password=None):
    # Open and return an authenticated SSH connection. (key_path/password default
    # to None, meaning "not provided" - then auth relies on the ssh-agent.)
    client = paramiko.SSHClient()                          # create an empty SSH client
    client.load_system_host_keys()                         # load known_hosts so we recognise the server
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # accept a first-time host key
    client.connect(                                        # actually open the connection
        hostname=host,
        username=username,
        key_filename=key_path,                             # use this key file if one was given
        password=password,                                 # or this password if one was given
        allow_agent=True,                                  # otherwise ask the ssh-agent (agent-first)
        look_for_keys=key_path is None,                    # only auto-search ~/.ssh when no key was passed
    )
    return client                                          # caller is responsible for closing it


def _detect_platform(client):
    # Decide if the connected target is Unix or Windows.
    # exec_command returns three streams: stdin, stdout, stderr. We ignore stdin
    # and stderr with "_" and keep stdout.
    _, stdout, _ = client.exec_command("uname -s 2>/dev/null")  # "uname" exists only on Unix
    # [REQUIREMENT: Casting] .read() gives raw bytes; .decode() casts them to a str
    # so we can .strip() it. If the string is non-empty -> Unix; empty -> Windows.
    return "unix" if stdout.read().decode(errors="replace").strip() else "windows"


def _run_command_set(client, commands):
    # Run every command in a {label: command} dict and collect the text output.
    raw_data = {}                                          # start with an empty result dict
    for label, command in commands.items():               # loop over each label/command pair
        _, stdout, _ = client.exec_command(command)        # run the command on the target
        # [REQUIREMENT: Casting] bytes -> str via .decode, then trim whitespace, then store.
        raw_data[label] = stdout.read().decode(errors="replace").strip()
    return raw_data                                        # dict of {label: output text}


def collect_system_info(host, username, key_path=None, password=None):
    # Public "read" step: SSH in, enumerate, return the raw output dict.
    client = _connect(host, username, key_path, password)  # open the connection
    try:                                                   # try/finally guarantees cleanup
        platform = _detect_platform(client)                # "unix" or "windows"
        # Choose the matching command set with a ternary expression.
        commands = UNIX_COMMANDS if platform == "unix" else WINDOWS_COMMANDS
        raw_data = _run_command_set(client, commands)      # run them all
        raw_data["platform"] = platform                    # remember which OS we detected
        return raw_data
    finally:
        client.close()                                     # always close, even if something raised


def execute_script(host, username, script, key_path=None, password=None):
    # Public "act" step: copy one approved script to the target, run it, return output.
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)
        if platform == "unix":
            # f-string builds the path; uuid4().hex is a random hex id so two runs never clash.
            remote_path = f"/tmp/.audit_{uuid.uuid4().hex}.py"
        else:
            # SFTP doesn't expand %TEMP% itself, so ask the shell what %TEMP% is first.
            _, stdout, _ = client.exec_command("echo %TEMP%")
            temp_dir = stdout.read().decode(errors="replace").strip()
            remote_path = f"{temp_dir}\\audit_{uuid.uuid4().hex}.py"

        # Open an SFTP channel and write the script text to the remote file.
        sftp = client.open_sftp()
        try:
            with sftp.open(remote_path, "w") as remote_file:  # "with" auto-closes the file
                remote_file.write(script)                     # write the script's source text
        finally:
            sftp.close()                                      # close the SFTP channel

        try:
            # Build the OS-appropriate "run it" and "delete it" commands.
            if platform == "unix":
                run_cmd = f"python3 {remote_path} || python {remote_path}"
                cleanup_cmd = f"rm -f {remote_path}"
            else:
                run_cmd = f"python {remote_path}"
                cleanup_cmd = f"del /f /q {remote_path}"

            _, stdout, stderr = client.exec_command(run_cmd)  # run the script, keep both streams
            # [REQUIREMENT: Casting] decode the byte streams into text strings.
            output = stdout.read().decode(errors="replace")   # what the script printed
            errors = stderr.read().decode(errors="replace")   # any error text
        finally:
            client.exec_command(cleanup_cmd)                  # always delete the temp script

        # Return both streams in a dict for report_writer to parse.
        return {"output": output, "errors": errors}
    finally:
        client.close()
