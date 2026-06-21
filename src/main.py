# main.py - the controller / entry point. It does little real work itself; it
# calls the other modules in order to run one full audit of one target.

import argparse   # standard library: parses command-line options like --target
import os          # [REQUIREMENT: Module os] os.environ reads the optional SSH password
import sys         # [REQUIREMENT: Module sys] sys.exit / sys.stderr for exit codes + errors

# Import the six worker modules. Each one has a single, separate job.
import target_connector   # SSH: collect info, run scripts
import system_profile     # parse raw info into a clean dict
import prompt_builder     # build the LLM prompts
import ai_client          # send prompts to the LLM
import validator          # safety-check the generated scripts
import report_writer      # save logs/scripts and write the PDF


# [REQUIREMENT: Functions] The program is split into functions instead of one
# long script. parse_args() handles the command line; main() runs the audit.
def parse_args():
    # Create the argument parser (the "description" shows up in --help).
    parser = argparse.ArgumentParser(
        description="Defensive AI Audit Framework - runs on controller, audits remote targets over SSH"
    )
    # Each add_argument defines one option. required=True means it must be given;
    # default=... supplies a value when the option is omitted.
    parser.add_argument("--target", required=True, help="Target machine IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username on target machine")
    parser.add_argument("--key", default=None, help="Path to SSH private key file (optional)")
    parser.add_argument("--output", default="reports/audit_report.pdf", help="Path for the final PDF report")
    # parse_args() reads sys.argv, validates it, and returns an object whose
    # attributes are the options (e.g. args.target).
    return parser.parse_args()


def main():
    args = parse_args()                              # read the command-line options

    # Read an optional SSH password from the environment. .get() returns None if
    # SSH_PASSWORD isn't set, in which case auth falls back to the ssh-agent/key.
    ssh_password = os.environ.get("SSH_PASSWORD")

    print(f"[*] Starting audit of target: {args.target}")   # status line for the user

    # --- Step 1: SSH in and collect raw, read-only system information ---
    raw_data = target_connector.collect_system_info(
        host=args.target,
        username=args.user,
        key_path=args.key,
        password=ssh_password,
    )

    # If we got nothing back, there is nothing to audit - stop here.
    if not raw_data:
        # [REQUIREMENT: Module sys] file=sys.stderr writes to the error stream;
        # sys.exit(1) ends the program with a non-zero (failure) status code.
        print("[ERROR] No system information collected from target.", file=sys.stderr)
        sys.exit(1)

    # --- Step 2: Parse the raw output into a structured profile dict ---
    # This also decides the platform (linux/windows), which selects OS-correct prompts.
    profile = system_profile.parse(raw_data)
    print(f"[*] System profile collected: {profile.get('os', 'unknown')} "
          f"/ {profile.get('arch', 'unknown')} ({profile.get('platform', 'unknown')})")

    # This dict accumulates everything; we hand it to report_writer at the end.
    # "tasks" gets one record per task; "findings"/"cves" are the combined totals.
    audit_data = {
        "target": args.target,
        "profile": profile,
        "tasks": [],
        "findings": [],
        "cves": [],
    }

    # --- Steps 3-7: handle one audit task at a time ---
    for task_key in prompt_builder.task_keys():      # loop over each task name
        print(f"\n[*] Task '{task_key}': requesting audit script from local LLM...")

        # A nested function (a "closure"). validator.validate_with_retries calls it
        # to produce each attempt. feedback is None first, then the validator's
        # complaints on a retry. _task_key=task_key captures THIS loop's value so
        # the closure doesn't accidentally use a later value of task_key.
        def generate(feedback, _task_key=task_key):
            system_prompt, user_prompt = prompt_builder.build_task_prompt(
                profile, _task_key, feedback=feedback
            )
            if feedback:                             # only true on a retry
                print(f"    retrying '{_task_key}' with validator feedback...")
            # Return the prompts plus the LLM's reply, all in one dict.
            return {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "ai_response": ai_client.send(system_prompt, user_prompt),
            }

        # The validator runs the generate -> check -> retry loop and reports back.
        outcome = validator.validate_with_retries(generate)

        # Record everything about this task (used by the report and the run log).
        task_result = {
            "task": task_key,
            "system_prompt": outcome["system_prompt"],
            "user_prompt": outcome["user_prompt"],
            "ai_response": outcome["ai_response"],
            "validation": outcome["validation"],
            "attempts": outcome["attempts"],
            # Ternary: "completed" if it passed, else "failed_validation".
            "status": "completed" if outcome["approved"] else "failed_validation",
            "script_output": None,
            "findings": [],
            "cves": [],
        }

        # If it never passed validation, log why and skip running it.
        if not outcome["approved"]:
            print(f"[!] Task '{task_key}' could not pass validation after "
                  f"{outcome['attempts']} attempt(s); skipping execution.")
            for issue in outcome["validation"]["issues"]:
                print(f"    - {issue}")
            audit_data["tasks"].append(task_result)  # still record the failed task
            continue                                 # jump to the next task in the loop

        # Approved: send the script to the target, run it, and capture its output.
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
        # Pull structured findings and CVEs out of the script's JSON output.
        task_result["findings"] = report_writer.extract_findings(script_output)
        task_result["cves"] = report_writer.extract_cves(script_output)

        # .extend adds all items from one list onto another (the running totals).
        audit_data["findings"].extend(task_result["findings"])
        audit_data["cves"].extend(task_result["cves"])
        audit_data["tasks"].append(task_result)      # save this task's record

    # --- Step 8: Save the run log (JSON) and each generated script to disk ---
    log_path = report_writer.save_run_log(audit_data)
    script_paths = report_writer.save_generated_scripts(audit_data)
    print(f"\n[*] Run log saved to: {log_path}")
    print(f"[*] Saved {len(script_paths)} generated script(s) to generated_scripts/")

    # --- Step 9: Build the final PDF report ---
    report_writer.write_pdf_report(audit_data, args.output)

    # --- Step 10: Print a short summary to the console ---
    tasks = audit_data["tasks"]
    # sum(1 for ... if ...) counts how many tasks have status "completed".
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


# This block runs only when the file is executed directly (python main.py),
# not when it is imported by another file.
if __name__ == "__main__":
    # try/except is a safety net: if anything inside main() raises an error
    # (failed SSH, unreachable LLM, ...), we catch it here instead of crashing ugly.
    try:
        main()
    except Exception as error:           # "Exception" catches any normal error
        # [REQUIREMENT: Module sys] report the problem on stderr and exit non-zero.
        print(f"[FATAL] Audit aborted: {error}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)                          # reached only on success: exit code 0 = OK
