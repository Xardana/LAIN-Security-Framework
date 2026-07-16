"""
main.py is the starting point of the program. It doesn't do much work itself -
instead it calls the six other files in the right order, kind of like a
recipe that tells each helper when to do its job.
"""

import argparse   # a library that reads the options typed on the command line.
import os          # [REQUIREMENT: Module os] os.environ reads the optional SSH password.
import sys         # [REQUIREMENT: Module sys] sys.exit (process exit codes) + sys.stderr (error stream).

# Bring in the six helper files. Each one has one job.
import target_connector   # SSH: read info from / run scripts on the target
import system_profile     # parse raw output into a clean dict
import prompt_builder     # build the LLM prompts
import ai_client          # send prompts to the LLM
import validator          # safety-check generated scripts
import report_writer      # save logs/scripts + write the PDF


"""[REQUIREMENT: Functions] The program is split into functions so that "reading the
command-line options" and "running the audit" each stay short and easy to follow."""
def parse_args():
    """This sets up the command-line options the program accepts, like --target
    and --user, and describes what each one is for."""
    parser = argparse.ArgumentParser(
        description="Defensive AI Audit Framework - runs on controller, audits remote targets over SSH"
    )
    parser.add_argument("--target", required=True, help="Target machine IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username on target machine")
    parser.add_argument("--key", default=None, help="Path to SSH private key file (optional)")
    parser.add_argument("--output", default="reports/audit_report.pdf", help="Path for the final PDF report")
    # This reads whatever the user typed and hands back a neat object with each option on it.
    return parser.parse_args()


def main():
    args = parse_args()                              # the orchestration begins

    # Look up an optional password from the environment; if it's not set, this is just empty.
    ssh_password = os.environ.get("SSH_PASSWORD")

    print(f"[*] Starting audit of target: {args.target}")

    # --- Step 1: SSH in and collect raw, read-only system information ---
    raw_data = target_connector.collect_system_info(
        host=args.target,
        username=args.user,
        key_path=args.key,
        password=ssh_password,
    )

    # If nothing came back, there's nothing to do, so stop here.
    if not raw_data:
        """If something goes wrong, we want the program to clearly say so and
        exit with an error status, so anything watching this program (like a
        script or another tool) knows the run failed."""
        print("[ERROR] No system information collected from target.", file=sys.stderr)
        sys.exit(1)

    # --- Step 2: Parse the raw output into a structured profile dict ---
    profile = system_profile.parse(raw_data)         # also figures out linux vs windows
    print(f"[*] System profile collected: {profile.get('os', 'unknown')} "
          f"/ {profile.get('arch', 'unknown')} ({profile.get('platform', 'unknown')})")

    """This is where we build up everything we've learned during the audit, one
    piece at a time, so we can hand it all to the report writer at the end."""
    audit_data = {
        "target": args.target,
        "profile": profile,
        "tasks": [],
        "findings": [],
        "cves": [],
    }

    # --- Steps 3-7: process one audit task at a time ---
    for task_key in prompt_builder.task_keys():      # go through each task name, one at a time
        print(f"\n[*] Task '{task_key}': requesting audit script from local LLM...")

        """This helper function asks the AI to write the script for this one
        task. We define it fresh inside the loop so it always remembers which
        task it's working on, even though the validator is the one that
        actually calls it."""
        def generate(feedback, _task_key=task_key):
            system_prompt, user_prompt = prompt_builder.build_task_prompt(
                profile, _task_key, feedback=feedback
            )
            if feedback:                             # only true when we're retrying
                print(f"    retrying '{_task_key}' with validator feedback...")
            # Bundle everything the validator needs to check into one package.
            return {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "ai_response": ai_client.send(system_prompt, user_prompt),
            }

        # Hand the "generate" helper to the validator, which will call it, check the
        # result, and retry if needed, then give us back the final outcome.
        outcome = validator.validate_with_retries(generate)

        # Keep a record of what happened for this task, for the report later.
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

        # If the script never passed the safety check, note why and don't run it.
        if not outcome["approved"]:
            print(f"[!] Task '{task_key}' could not pass validation after "
                  f"{outcome['attempts']} attempt(s); skipping execution.")
            for issue in outcome["validation"]["issues"]:
                print(f"    - {issue}")
            audit_data["tasks"].append(task_result)  # still keep a record of the failed task
            continue                                 # move on to the next task

        # It passed the safety check: upload and run the script on the target, and grab its output.
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
        # Pull out the structured findings and CVE ids from what the script printed.
        task_result["findings"] = report_writer.extract_findings(script_output)
        task_result["cves"] = report_writer.extract_cves(script_output)

        # Add this task's findings/CVEs onto the running totals for the whole audit.
        audit_data["findings"].extend(task_result["findings"])
        audit_data["cves"].extend(task_result["cves"])
        audit_data["tasks"].append(task_result)      # keep this task's full record

    # --- Step 8: persist the run log (JSON) and each generated script to disk ---
    log_path = report_writer.save_run_log(audit_data)
    script_paths = report_writer.save_generated_scripts(audit_data)
    print(f"\n[*] Run log saved to: {log_path}")
    print(f"[*] Saved {len(script_paths)} generated script(s) to generated_scripts/")

    # --- Step 9: build the final PDF report ---
    report_writer.write_pdf_report(audit_data, args.output)

    # --- Step 10: print a short console summary ---
    tasks = audit_data["tasks"]
    # Count how many tasks ended up "completed".
    completed = sum(1 for t in tasks if t["status"] == "completed")
    incomplete = len(tasks) - completed
    print("\n[+] Audit complete.")
    print(f"    Target   : {args.target}")
    print(f"    OS       : {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})")
    # Only mention incomplete tasks if there actually were any.
    print(f"    Tasks    : {completed}/{len(tasks)} completed"
          + (f", {incomplete} could not be completed" if incomplete else ""))
    print(f"    Findings : {len(audit_data['findings'])}")
    print(f"    CVEs     : {len(audit_data['cves'])}")
    print(f"[*] PDF report saved to: {args.output}")


"""This last bit only runs when you launch this file directly (like typing
`python main.py`), not when some other file imports it. It's the program's
actual "on" switch."""
if __name__ == "__main__":
    """If anything goes wrong anywhere in main() - like the SSH connection
    failing or the AI being unreachable - we catch it here so the user gets a
    clean error message instead of a scary wall of technical text."""
    try:
        main()
    except Exception as error:           # catch any normal error and give it the name "error"
        # [REQUIREMENT: Module sys] report on stderr, exit non-zero so callers know it failed.
        print(f"[FATAL] Audit aborted: {error}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)                          # only reached if everything went fine; 0 means success
