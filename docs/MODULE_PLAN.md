# Source File Descriptions

## `src/main.py`

`main.py` is the main controller for the project. It connects all the other modules together and controls the full program workflow.

It will:

* Start the program
* Call `system_profile.py` to collect system information
* Call `prompt_builder.py` to build the AI prompts
* Call `ai_client.py` to send the prompt to the AI API
* Receive the AI-generated script response
* Call `validator.py` to check whether the generated script is safe
* Save approved generated scripts
* Call `report_writer.py` to save logs and reports
* Print a clear summary for the user

This file should not contain all the logic itself. It should mostly coordinate the other files. Think of it as the project manager, except useful.

---

## `src/system_profile.py`

`system_profile.py` collects safe, read-only information about the machine the script is running on.

It will collect information such as:

* Operating system
* OS version
* Python version
* CPU information
* Memory information
* Machine architecture
* Current user privilege level
* Basic network interface information
* Available tools, such as Python, PowerShell, Bash, `ipconfig`, or `ip`

It should not collect sensitive personal data or secrets.

It must not collect:

* Passwords
* Browser cookies
* Tokens
* SSH keys
* API keys
* Private documents
* Browser history

The purpose of this file is to create a basic system profile that can be safely sent to the AI model.

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

The files work together like this:

```text
main.py
  ↓
system_profile.py
  ↓
prompt_builder.py
  ↓
ai_client.py
  ↓
validator.py
  ↓
report_writer.py
```

## Full Project Flow

```text
1. main.py starts the program
2. system_profile.py collects safe system information
3. prompt_builder.py turns that information into an AI prompt
4. ai_client.py sends the prompt to the AI API
5. The AI returns a proposed defensive audit script
6. validator.py checks the generated script for unsafe behavior
7. main.py saves approved scripts or rejects unsafe ones
8. report_writer.py saves reports, logs, and results
```

## Key Rule

Each file should have one main responsibility.

Do not dump everything into `main.py`.

A clean project separates responsibilities so each file is easier to understand, test, and fix.
