# Source File Descriptions

## `src/main.py`

`main.py` is the main controller for the project. It connects all the other modules together and controls the full program workflow. It runs entirely on the controller machine (the non-vulnerable machine).

It will:

* Start the program
* Accept target machine connection details (IP/hostname, SSH credentials)
* Call `target_connector.py` to SSH into the target and collect remote system information
* Call `system_profile.py` to parse and structure the remotely collected data
* Call `prompt_builder.py` to build the AI prompts
* Call `ai_client.py` to send the prompt to the local LLM API
* Receive the AI-generated script response
* Call `validator.py` to check whether the generated script is safe
* Call `target_connector.py` to execute the validated script on the target machine
* Call `report_writer.py` to save logs and reports
* Print a clear summary for the user

This file should not contain all the logic itself. It should mostly coordinate the other files. Think of it as the project manager, except useful.

---

## `src/target_connector.py`

`target_connector.py` handles all SSH communication between the controller machine and the remote target machines. This is the module that allows the framework to run on a safe, non-vulnerable controller while auditing remote vulnerable machines.

It will:

* Accept connection details: target IP/hostname, SSH username, and credential (password or key path)
* Open an SSH connection to the target machine using `paramiko` or a similar library
* Run read-only enumeration commands on the target to collect system information
* Return the raw command output to `system_profile.py` for parsing
* Transfer the validated audit script to the target machine
* Execute the audit script on the target machine
* Capture and return the output back to the controller
* Close the SSH connection cleanly after each operation

Connection details must come from environment variables or a local `.env` file. SSH credentials must never be hardcoded.

It must not:

* Execute any script on the target that has not been approved by `validator.py`
* Modify, delete, or write persistent files on the target beyond the temporary audit script
* Leave SSH sessions open after a task is complete

---

## `src/system_profile.py`

`system_profile.py` parses and structures the raw system information collected from the remote target machine by `target_connector.py`.

It will parse information such as:

* Operating system
* OS version
* Python version
* CPU information
* Memory information
* Machine architecture
* Current user privilege level
* Basic network interface information
* Available tools, such as Python, PowerShell, Bash, `ipconfig`, or `ip`

It should not collect sensitive personal data or secrets, and must not request or parse:

* Passwords
* Browser cookies
* Tokens
* SSH keys
* API keys
* Private documents
* Browser history

The purpose of this file is to take raw remote command output and produce a clean, structured profile that can be safely sent to the AI model.

---

## `src/prompt_builder.py`

`prompt_builder.py` creates the prompts that will be sent to the AI API.

It will build two main prompt types:

1. A system prompt that defines the AI’s role and safety rules.
2. A user prompt that includes the collected system profile and asks for a machine-specific defensive audit script.

The prompts should clearly state that the project is:

* Defensive
* Authorized
* Read-only
* Focused on auditing
* Not allowed to exploit, steal credentials, escalate privileges, create persistence, or modify the system

This file does not contact the AI API. It only builds the text prompts.

---

## `src/ai_client.py`

`ai_client.py` handles communication with the AI API.

It will:

* Load the API key from an environment variable
* Send the system prompt and user prompt to the AI model
* Receive the AI response
* Parse the response into structured JSON
* Return the generated script data back to `main.py`

This file should not collect system information, validate generated code, or write reports. Its only job is API communication.

Important safety rule: API keys must never be hardcoded into this file. They should be loaded from environment variables or a local `.env` file that is not committed to GitHub.

---

## `src/validator.py`

`validator.py` checks the AI-generated Python code before it is saved or allowed to run.

It will look for unsafe behavior such as:

* File deletion
* Credential collection
* Token or cookie collection
* Privilege escalation attempts
* Persistence mechanisms
* Security tool disabling
* Suspicious shell commands
* Dangerous use of `eval()` or `exec()`
* Unauthorized network connections
* Destructive commands

The validator should return whether the generated script is approved or rejected.

Example return structure:

```python
{
    "approved": False,
    "issues": ["Blocked pattern found: os.remove"],
    "warnings": []
}
```

This module is important because AI-generated code should not be trusted blindly. Blindly running generated code is how people turn a school project into a tiny disaster factory.

---

## `src/report_writer.py`

`report_writer.py` saves project output into readable files.

It will save things such as:

* System profile results
* AI prompts
* AI responses
* Validation results
* Generated script metadata
* Final audit reports

It should support saving reports in formats such as:

* `.txt`
* `.json`
* possibly `.md` later

This file helps prove what the tool did during testing. It also makes the project easier to grade because the instructor can see clear evidence of the workflow instead of guessing from terminal chaos.

---

# Simple Workflow Summary

The controller machine runs all Python modules. The target machine (vulnerable machine) is only reached via SSH.

```text
main.py
  ↓
target_connector.py  (SSH → target: collect system info)
  ↓
system_profile.py    (parse remote data on controller)
  ↓
prompt_builder.py
  ↓
ai_client.py         (local LLM API on controller)
  ↓
validator.py
  ↓
target_connector.py  (SSH → target: execute validated script)
  ↓
report_writer.py
```

## Full Project Flow

```text
1. main.py starts the program on the controller machine
2. target_connector.py SSHes into the target and runs read-only enumeration commands
3. system_profile.py parses the raw remote output into a structured profile
4. prompt_builder.py turns that profile into an AI prompt
5. ai_client.py sends the prompt to the local LLM API (runs on controller)
6. The AI returns a proposed defensive audit script
7. validator.py checks the generated script for unsafe behavior
8. target_connector.py transfers and executes the approved script on the target
9. report_writer.py saves all results, logs, and reports on the controller
```

## Key Rule

Each file should have one main responsibility.

Do not dump everything into `main.py`.

A clean project separates responsibilities so each file is easier to understand, test, and fix.
