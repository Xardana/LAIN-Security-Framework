# Defensive-AI-Audit-Framework

## Overview

Defensive AI Audit Framework is a Python-based defensive cybersecurity research project. The goal of the project is to explore whether AI API calls can be used to generate machine-specific auditing scripts based on the system where the tool is running.

Traditional audit scripts are often static. They usually run the same checks on every machine, even when some checks are irrelevant to the operating system, hardware, installed software, permissions, or available tools. This project takes a different approach. A base Python controller collects basic system information, sends that information to an AI model through an API call, and receives a proposed Python auditing script tailored to that machine.

This project is designed for authorized defensive auditing, system inventory, and cybersecurity education only.

## Project Purpose

The purpose of this project is to build a proof-of-concept adaptive auditing framework that can:

* Collect basic local system information
* Build structured prompts for an AI model
* Request machine-specific defensive audit scripts
* Validate generated scripts before execution
* Run only safe, read-only checks
* Save results into logs and reports
* Compare adaptive auditing against static auditing scripts

## Cybersecurity Justification

This project explores how AI can assist defensive cybersecurity workflows. In real environments, security analysts and system administrators often need to understand a machine’s configuration quickly. Static scripts may waste time running irrelevant checks or may fail to adapt to different environments. An adaptive system could help generate more relevant checks based on the machine’s operating system, installed software, available tools, permissions, and security settings.

The project also has research value because similar AI-assisted scripting concepts have been discussed in the context of cyber attackers. This project reworks the concept from a defensive perspective to better understand how adaptive AI-generated scripting works, what risks it creates, and what safety controls are needed.

## Scope

This project will focus on:

* Local system inventory
* Defensive security auditing
* Read-only system checks
* AI-assisted script generation
* Generated code validation
* Report generation
* Testing in authorized lab virtual machines

## Out of Scope

This project will not include:

* Exploitation
* Privilege escalation
* Credential theft
* Browser cookie or token collection
* Persistence
* Evasion
* Malware behavior
* Unauthorized scanning
* Disabling security tools
* Destructive file or system changes

## Planned Architecture

The project will use a modular Python structure. All modules run on the **controller machine** (a safe, non-vulnerable machine). Target machines (vulnerable machines) are only reached over SSH — no framework code runs on them directly.

1. The base Python controller runs on an authorized, non-vulnerable machine.
2. The target connector SSHes into the remote target machine and collects read-only system information.
3. The system profiler parses the raw remote data into a structured profile on the controller.
4. The prompt builder formats the structured profile into an AI prompt.
5. The AI client sends the prompt to a local LLM API running on the controller.
6. The AI model returns a proposed machine-specific Python auditing script.
7. The validator checks the generated script for unsafe behavior before any execution.
8. The target connector transfers and executes the approved script on the remote target machine.
9. Results are written to logs and reports on the controller.

## Current Phase

The current phase focuses on project planning and design. This includes:

* Defining the project idea
* Creating the GitHub repository
* Writing the README
* Designing the flowchart
* Documenting the ethical and defensive scope
* Planning the Python module structure

No offensive functionality will be developed.

## Final Planned Functionality

By the final version, the project aims to include:

* SSH-based remote connection to target machines from a safe controller machine
* Basic Windows and Linux system profiling collected remotely over SSH
* AI-generated defensive auditing scripts tailored to each target's profile
* Safety validation for generated code before any remote execution
* Restricted remote execution workflow via SSH
* Logging of prompts, AI responses, and script results on the controller
* Final audit deliverable as a paginated PDF report including system profile, findings, evidence, and any referenced CVEs
* Testing across authorized Windows and Linux lab machines
* Documentation explaining the project design, risks, and limitations

## Safety Controls

The project will include safety controls to reduce the risk of unsafe AI-generated code. These controls may include:

* Prompt-level restrictions
* Generated code review
* Blocked keyword and behavior checks
* Read-only execution rules
* Logging of generated scripts
* Manual approval before execution
* Controlled lab testing only

## Disclosure Statement

This project idea was inspired by a BSides cybersecurity presentation discussing how cyber attackers may use AI API calls and dynamically generated scripts for adaptive enumeration or research. This project does not copy code, tools, or exact implementation details from that presentation. Instead, it is a defensive and educational reinterpretation of the general concept.

If any specific materials, diagrams, terminology, or implementation ideas from the presentation or other outside sources are used, they will be cited properly in the project documentation.

## Ethical Use Statement

This project is intended only for authorized defensive cybersecurity research and education. It should only be run on systems where the user has explicit permission. The tool is not intended for attacking systems, collecting credentials, bypassing security controls, or performing unauthorized reconnaissance.

## Repository Structure

```text
adaptive-ai-system-auditor/
│
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
│
├── docs/
│   ├── project-proposal.md
│   ├── flowchart.md
│   └── disclosure-statement.md
│
├── src/
│   ├── main.py
│   ├── target_connector.py
│   ├── system_profile.py
│   ├── prompt_builder.py
│   ├── ai_client.py
│   ├── validator.py
│   └── report_writer.py
│
├── generated_scripts/
│   └── .gitkeep
│
├── reports/
│   └── .gitkeep
│
├── logs/
│   └── .gitkeep
│
└── tests/
    └── test_placeholder.py
```

## Status

Project status: Planning and design phase.

## License

This project is for educational use. A license will be selected before public release.
