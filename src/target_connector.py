"""
This file handles all the SSH talking to the target machines. The program runs on a
safe "controller" computer and never installs anything on the target, it just connects
in over SSH to read info and, on the old path, run one approved script. Keeping every
SSH detail in here means the rest of the program can just say "collect_system_info" or
"run_commands" without knowing anything about SSH.
"""

import socket          # we don't open sockets ourselves, we just want its "timed out" error type.
import uuid            # makes a random one-of-a-kind id, so each temp script we upload gets
                       # a name that can never clash with another run's.

import paramiko        # [REQUIREMENT: Module] the library that speaks SSH for us, so we don't
                       # have to shell out to a separate `ssh` program.

# How long we'll wait, in seconds, before giving up. Without these, a flaky link or a
# script hung waiting for input would leave us stuck forever with no output and no
# error, which is the worst way to fail. The audit script gets a much longer leash than
# the quick info commands, since it has real work to do.
CONNECT_TIMEOUT = 15   # waiting for the target to answer the door
COMMAND_TIMEOUT = 30   # one small read-only info command
SCRIPT_TIMEOUT = 120   # the full audit script

# Short label -> the shell command that produces it, for Linux. Every command here is
# read-only. Two shell notes: "2>/dev/null" just hides error messages, and "a || b"
# means "try a, and only run b if a fails".
UNIX_COMMANDS = {
    "os": "uname -a",                                              # kernel/OS summary line
    "os_release": "cat /etc/os-release 2>/dev/null",              # distro name + version
    "python_version": "python3 --version 2>/dev/null || python --version 2>/dev/null",
    "cpu": "lscpu 2>/dev/null || cat /proc/cpuinfo 2>/dev/null",  # CPU model/cores
    "memory": "free -h 2>/dev/null",                             # RAM in human-readable units
    "arch": "uname -m",                                          # architecture, e.g. x86_64
    "whoami": "whoami",                                          # current username
    "network": "ip addr 2>/dev/null || ifconfig 2>/dev/null",   # network interfaces
    "tools": "for t in python3 python powershell bash ip ifconfig; do command -v $t; done",
    "packages": "python3 -m pip list 2>/dev/null || pip3 list 2>/dev/null || pip list 2>/dev/null",
}

# The same checks for Windows. "2>nul" is the Windows way of hiding errors. We need a
# separate list because Windows and Linux show the same info through totally different
# commands.
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
    """Open one SSH connection to the target. Keeping this in one helper means all our
    login rules live in one place. With no key or password given, it falls back to
    whatever the ssh-agent already knows, so our own code never handles a secret
    directly."""
    client = paramiko.SSHClient()                          # make the SSH client
    # Read the local machine's list of known, trusted servers.
    client.load_system_host_keys()
    # Never seen this server before? Just trust it. (A later version plans to make this
    # stricter and reject unknown servers.)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Connect and log in.
    client.connect(
        hostname=host,
        username=username,
        key_filename=key_path,                             # use this private key file if given
        password=password,                                 # or this password if given
        allow_agent=True,                                  # otherwise ask the running ssh-agent
        look_for_keys=key_path is None,                    # only search ~/.ssh if no key was passed in
        timeout=CONNECT_TIMEOUT,                           # give up if the target never answers
        banner_timeout=CONNECT_TIMEOUT * 2,                # or answers but never introduces itself
        auth_timeout=CONNECT_TIMEOUT * 2,                  # or stalls partway through logging in
    )
    return client                                          # the caller is responsible for closing this


def _read_text(stream):
    """Read everything a command printed and turn it into text.
    [REQUIREMENT: Casting] If we run out of patience waiting, we let that error travel
    up to whoever called us, because only they know whether a slow command is a shrug or
    a real problem worth reporting."""
    return stream.read().decode(errors="replace")


def _detect_platform(client):
    """Every other step depends on knowing the target's OS, so we check it once, right
    at the start."""
    # `uname` only exists on Unix-like systems, so if this prints anything, it's Unix.
    _, stdout, _ = client.exec_command("uname -s 2>/dev/null", timeout=COMMAND_TIMEOUT)
    # Something back means Unix, nothing means Windows.
    return "unix" if _read_text(stdout).strip() else "windows"


def _run_command_set(client, commands):
    """Run a whole {label: command} dict and hand back a matching {label: output} dict.
    Reusing this one function for both operating systems saves writing the loop twice."""
    raw_data = {}                                          # the results we build up
    for label, command in commands.items():
        # If one command is broken or slow, just record a blank and move on. One awkward
        # command shouldn't cost us the whole profile.
        try:
            _, stdout, _ = client.exec_command(command, timeout=COMMAND_TIMEOUT)
            raw_data[label] = _read_text(stdout).strip()
        except (socket.timeout, paramiko.SSHException):
            raw_data[label] = ""
    return raw_data


def run_commands(host, username, commands, key_path=None, password=None):
    """Run a batch of read-only commands and report exactly how each one went.

    This is what the collectors use. It differs from _run_command_set above in one
    important way: it keeps the error output AND the exit code, not just what was
    printed. Sounds like a detail, but it's the whole point. A command that fails often
    still prints something, and treating that something as a result is exactly how we
    ended up reporting a strict firewall policy from the text of an error message. With
    the exit code in hand, the collectors can tell "I looked and found nothing" apart
    from "I wasn't allowed to look", which are very different answers."""
    client = _connect(host, username, key_path, password)
    try:
        results = {}
        for label, command in commands.items():
            try:
                _, stdout, stderr = client.exec_command(command, timeout=COMMAND_TIMEOUT)
                output = _read_text(stdout)
                errors = _read_text(stderr)
                # Ask the channel how the command actually ended. 0 is success, anything
                # else is a failure, however chatty it was on the way out.
                exit_code = stdout.channel.recv_exit_status()
            except socket.timeout:
                output, errors, exit_code = "", f"timed out after {COMMAND_TIMEOUT}s", -1
            except paramiko.SSHException as problem:
                output, errors, exit_code = "", f"ssh error: {problem}", -1
            results[label] = {
                "stdout": output,
                "stderr": errors,
                "exit_code": exit_code,
                "command": command,
            }
        return results
    finally:
        client.close()


def collect_system_info(host, username, key_path=None, password=None):
    """The public "read" step. Always closes the connection when it's done, even if
    something goes wrong partway through."""
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)                # "unix" or "windows"
        commands = UNIX_COMMANDS if platform == "unix" else WINDOWS_COMMANDS  # pick the matching list
        raw_data = _run_command_set(client, commands)
        raw_data["platform"] = platform                    # note the OS so later steps don't re-check
        return raw_data
    finally:
        # Always runs, success or failure, so we never leave a connection open by accident.
        client.close()


def execute_script(host, username, script, key_path=None, password=None):
    """The old "act" step, from before we switched to collectors. Uploads one
    already-approved script, runs it, grabs what it printed, then deletes it, leaving
    nothing behind on the target. The main program doesn't call this anymore, but it's
    kept as the "before" half of the comparison."""
    client = _connect(host, username, key_path, password)
    try:
        platform = _detect_platform(client)
        if platform == "unix":
            # A random filename means two runs at the same time can never collide.
            remote_path = f"/tmp/.audit_{uuid.uuid4().hex}.py"
        else:
            # On Windows we ask the shell for the temp folder first, then build our path.
            _, stdout, _ = client.exec_command("echo %TEMP%", timeout=COMMAND_TIMEOUT)
            temp_dir = _read_text(stdout).strip()
            remote_path = f"{temp_dir}\\audit_{uuid.uuid4().hex}.py"

        # Open a file-transfer channel over the same SSH connection.
        sftp = client.open_sftp()
        try:
            # Write the script text to the target, and make sure the file gets closed
            # afterward no matter what.
            with sftp.open(remote_path, "w") as remote_file:  # "w" = open for writing
                remote_file.write(script)
        finally:
            sftp.close()                                      # close the file-transfer channel

        try:
            # Build the right "run it" and "clean up" commands for this OS.
            if platform == "unix":
                # Pick the interpreter first, then run the script exactly once. This used
                # to say "python3 script || python script", but "||" means "if the left
                # side fails, run the right side", and it counts ANY failure, not just a
                # missing python3. So a script that simply hit an error quietly ran a
                # second time, and we got two sets of results jumbled together in the
                # output, which nothing downstream could read.
                run_cmd = (f"if command -v python3 >/dev/null 2>&1; "
                           f"then python3 {remote_path}; else python {remote_path}; fi")
                cleanup_cmd = f"rm -f {remote_path}"
            else:
                run_cmd = f"python {remote_path}"
                cleanup_cmd = f"del /f /q {remote_path}"

            try:
                # Keep both the normal output and any error messages.
                _, stdout, stderr = client.exec_command(run_cmd, timeout=SCRIPT_TIMEOUT)
                output = _read_text(stdout)               # the script's printed JSON
                errors = _read_text(stderr)               # any error/traceback text
            except socket.timeout:
                # The script ran too long and we stopped waiting. Say so plainly instead
                # of returning an empty result that looks like a clean run.
                output = ""
                errors = f"Script did not finish within {SCRIPT_TIMEOUT} seconds; gave up waiting."
        finally:
            # Always delete the temp script, even if running it went wrong, so nothing is
            # left behind on the target. Note the read on the next line: asking the target
            # to delete something only SENDS the request, so without waiting for it to
            # finish we'd hang up the connection below before the target got round to it,
            # and the file would quietly stay there.
            try:
                _, cleanup_out, _ = client.exec_command(cleanup_cmd, timeout=COMMAND_TIMEOUT)
                _read_text(cleanup_out)                   # waits until the delete has actually happened
            except (socket.timeout, paramiko.SSHException):
                pass                                      # best effort, never mask the real result

        # Hand back both streams; report_writer reads "output" as JSON.
        return {"output": output, "errors": errors}
    finally:
        client.close()
