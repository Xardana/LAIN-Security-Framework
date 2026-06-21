"""
main.py
=======
The controller / entry point of the Defensive AI Audit Framework. This file is
the "project manager": it does very little real work itself and instead calls
the other modules in order. Run it on a machine you control to audit a remote
target over SSH.

Pipeline (each step is one other module):
    target_connector -> system_profile -> prompt_builder -> ai_client
        -> validator -> target_connector (run) -> report_writer

Coding requirements demonstrated in THIS file:
    * Functions - parse_args() and main() organise the program into defs.
    * Modules   - standard-library `os` (read the optional SSH password from the
                  environment) and `sys` (set the process exit code and print
                  fatal errors to standard error).
"""

import argparse   # standard library: parse command-line options
import os          # [REQUIREMENT: Module os] read the optional SSH password from env
import sys         # [REQUIREMENT: Module sys] process exit codes + error reporting

# The six worker modules, each with a single responsibility.
import target_connector
import system_profile
import prompt_builder
import ai_client
import validator
import report_writer


# [REQUIREMENT: Functions] The entire program is organised into functions -
# parse_args() and main() here, plus one focused function per job in every other
# module - rather than one long script. This is a representative example.
def parse_args():
    """Define and read the command-line arguments, returning the parsed values.

    Keeping argument parsing in its own function keeps main() focused on the
    actual audit flow.
    """
    parser = argparse.ArgumentParser(
        description="Defensive AI Audit Framework - runs on controller, audits remote targets over SSH"
    )
    parser.add_argument("--target", required=True, help="Target machine IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username on target machine")
    parser.add_argument("--key", default=None, help="Path to SSH private key file (optional)")
    parser.add_argument("--output", default="reports/audit_report.pdf", help="Path for the final PDF report")
    return parser.parse_args()


def main():
    """Run the whole audit pipeline for one target, from SSH to finished PDF."""
    args = parse_args()

    # Auth is agent-first (ssh-agent / Pageant) by default; --key and the
    # SSH_PASSWORD environment variable are optional fallbacks for machines
    # without agent access.
    ssh_password = os.environ.get("SSH_PASSWORD")

    print(f"[*] Starting audit of target: {args.target}")

    # Step 1: SSH into target and collect raw, read-only system information.
    raw_data = target_connector.collect_system_info(
        host=args.target,
        username=args.user,
        key_path=args.key,
        password=ssh_password,
    )

    # If the target returned nothing usable there is no point continuing.
    if not raw_data:
        # [REQUIREMENT: Module sys] report on standard error and exit non-zero
        # so any caller/automation knows the run failed.
        print("[ERROR] No system information collected from target.", file=sys.stderr)
        sys.exit(1)

    # Step 2: Parse raw remote data into a structured profile. This also decides
    # the target platform (linux/windows), which drives OS-correct prompt
    # selection below.
    profile = system_profile.parse(raw_data)
    print(f"[*] System profile collected: {profile.get('os', 'unknown')} "
          f"/ {profile.get('arch', 'unknown')} ({profile.get('platform', 'unknown')})")

    # Accumulator passed to report_writer at the end. "tasks" holds one record
    # per audit task; "findings"/"cves" are the flattened totals across tasks.
    audit_data = {
        "target": args.target,
        "profile": profile,
        "tasks": [],
        "findings": [],
        "cves": [],
    }

    # Step 3-7: Audit one small, OS-specific task at a time. Each task is sent to
    # the local LLM and must pass the validator before it ever runs on the
    # target. If it fails, the validator asks the model to try again (up to its
    # max); if all attempts fail, the task is recorded as not completed so the
    # report shows why instead of leaving a blank section.
    for task_key in prompt_builder.task_keys():
        print(f"\n[*] Task '{task_key}': requesting audit script from local LLM...")

        # This inner callback is what validator.validate_with_retries() calls to
        # produce each attempt. `feedback` is None on the first try, then the
        # validator's objections on retries so the prompt can ask for a fix.
        # (_task_key binds the current loop value into the closure.)
        def generate(feedback, _task_key=task_key):
            system_prompt, user_prompt = prompt_builder.build_task_prompt(
                profile, _task_key, feedback=feedback
            )
            if feedback:
                print(f"    retrying '{_task_key}' with validator feedback...")
            return {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "ai_response": ai_client.send(system_prompt, user_prompt),
            }

        # The validator drives the generate-check-retry loop and reports back.
        outcome = validator.validate_with_retries(generate)

        # Record everything about this task for the report and the run log.
        task_result = {
            "task": task_key,
            "system_prompt": outcome["system_prompt"],
            "user_prompt": outcome["user_prompt"],
            "ai_response": outcome["ai_response"],
            "validation": outcome["validation"],
            "attempts": outcome["attempts"],
            "status": "completed" if outcome["approved"] else "failed_validation",
            "script_output": None,
            "findings": [],
            "cves": [],
        }

        # Rejected after all retries: never execute it, just log why and move on.
        if not outcome["approved"]:
            print(f"[!] Task '{task_key}' could not pass validation after "
                  f"{outcome['attempts']} attempt(s); skipping execution.")
            for issue in outcome["validation"]["issues"]:
                print(f"    - {issue}")
            audit_data["tasks"].append(task_result)
            continue

        # Approved: transfer and run the script on the target, then collect output.
        print(f"[*] Task '{task_key}' approved on attempt {outcome['attempts']}. "
              f"Executing on target...")
        script_output = target_connector.execute_script(
            host=args.target,
            username=args.user,
            script=outcome["ai_response"]["script"],
            key_path=args.key,
            password=ssh_password,
        )
        task_result["script_output"] = script_output
        task_result["findings"] = report_writer.extract_findings(script_output)
        task_result["cves"] = report_writer.extract_cves(script_output)

        # Roll this task's findings/CVEs up into the overall totals.
        audit_data["findings"].extend(task_result["findings"])
        audit_data["cves"].extend(task_result["cves"])
        audit_data["tasks"].append(task_result)

    # Step 8: Persist artifacts for auditability and manual review - a JSON log
    # of everything collected and generated, plus each generated script on disk.
    log_path = report_writer.save_run_log(audit_data)
    script_paths = report_writer.save_generated_scripts(audit_data)
    print(f"\n[*] Run log saved to: {log_path}")
    print(f"[*] Saved {len(script_paths)} generated script(s) to generated_scripts/")

    # Step 9: Generate the final PDF report with full pagination, findings, and CVEs.
    report_writer.write_pdf_report(audit_data, args.output)

    # Step 10: Print a short human-readable summary to the console.
    tasks = audit_data["tasks"]
    completed = sum(1 for t in tasks if t["status"] == "completed")
    incomplete = len(tasks) - completed
    print("\n[+] Audit complete.")
    print(f"    Target   : {args.target}")
    print(f"    OS       : {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})")
    print(f"    Tasks    : {completed}/{len(tasks)} completed"
          + (f", {incomplete} could not be completed" if incomplete else ""))
    print(f"    Findings : {len(audit_data['findings'])}")
    print(f"    CVEs     : {len(audit_data['cves'])}")
    print(f"[*] PDF report saved to: {args.output}")


if __name__ == "__main__":
    # Top-level safety net: turn any unexpected error (failed SSH, unreachable
    # LLM, etc.) into a clear message on standard error and a non-zero exit code,
    # while a clean run exits with 0.
    try:
        main()
    except Exception as error:        # deliberate catch-all at the program boundary
        # [REQUIREMENT: Module sys] write to stderr and exit with a failure code.
        print(f"[FATAL] Audit aborted: {error}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
