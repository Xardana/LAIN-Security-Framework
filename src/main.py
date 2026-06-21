# main.py - the CONTROLLER / entry point. Architectural role: this is the "orchestrator."
# It contains almost no business logic itself; instead it wires the six single-purpose modules
# together in the right order. Keeping orchestration separate from the workers makes each worker
# independently testable and makes the high-level flow readable in one place.

import argparse   # stdlib: declarative command-line parsing (turns sys.argv into typed options).
import os          # [REQUIREMENT: Module os] os.environ reads the optional SSH password.
import sys         # [REQUIREMENT: Module sys] sys.exit (process exit codes) + sys.stderr (error stream).

# Import the six workers. Each name is the module's single responsibility.
import target_connector   # SSH: read info from / run scripts on the target
import system_profile     # parse raw output into a clean dict
import prompt_builder     # build the LLM prompts
import ai_client          # send prompts to the LLM
import validator          # safety-check generated scripts
import report_writer      # save logs/scripts + write the PDF


# [REQUIREMENT: Functions] The program is decomposed into functions. WHY: separating "read the
# arguments" from "run the audit" keeps each function short and single-purpose.
def parse_args():
    # WHY (logic): argparse gives us --help, validation, and typed access for free.
    # HOW (syntax): ArgumentParser() builds a parser object; each .add_argument() declares one
    # flag. required=True makes argparse error out if it's missing; default=... supplies a value
    # when the flag is omitted. The "description"/"help" strings appear in --help output.
    parser = argparse.ArgumentParser(
        description="Defensive AI Audit Framework - runs on controller, audits remote targets over SSH"
    )
    parser.add_argument("--target", required=True, help="Target machine IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username on target machine")
    parser.add_argument("--key", default=None, help="Path to SSH private key file (optional)")
    parser.add_argument("--output", default="reports/audit_report.pdf", help="Path for the final PDF report")
    # parse_args() reads sys.argv UNDER THE HOOD, validates it, and returns a Namespace object
    # whose attributes are the parsed values (e.g. the parsed --target is available as args.target).
    return parser.parse_args()


def main():
    args = parse_args()                              # the orchestration begins

    # os.environ.get("SSH_PASSWORD") returns the env var's value, or None if it isn't set.
    # WHY: password is optional - if absent, paramiko falls back to the ssh-agent or a key file.
    ssh_password = os.environ.get("SSH_PASSWORD")

    print(f"[*] Starting audit of target: {args.target}")   # f-string interpolates args.target

    # --- Step 1: SSH in and collect raw, read-only system information ---
    # Arguments passed BY KEYWORD for readability. This returns a dict of {label: raw output}.
    raw_data = target_connector.collect_system_info(
        host=args.target,
        username=args.user,
        key_path=args.key,
        password=ssh_password,
    )

    # `not raw_data` is True for None or an EMPTY dict (both falsy). Nothing collected = nothing to do.
    if not raw_data:
        # WHY (logic): a CLI tool should signal failure through its EXIT CODE so scripts/CI can detect it.
        # HOW (syntax): print(..., file=sys.stderr) writes to the standard ERROR stream (stderr), kept
        # separate from normal output (stdout). sys.exit(1) ends the process with status 1 (non-zero = failure).
        print("[ERROR] No system information collected from target.", file=sys.stderr)
        sys.exit(1)

    # --- Step 2: Parse the raw output into a structured profile dict ---
    profile = system_profile.parse(raw_data)         # also decides linux/windows (drives OS-correct prompts)
    print(f"[*] System profile collected: {profile.get('os', 'unknown')} "
          f"/ {profile.get('arch', 'unknown')} ({profile.get('platform', 'unknown')})")

    # An accumulator dict we grow as we go, then hand to report_writer. "tasks" gets one record per
    # task; "findings"/"cves" are the flattened totals across all tasks.
    audit_data = {
        "target": args.target,
        "profile": profile,
        "tasks": [],
        "findings": [],
        "cves": [],
    }

    # --- Steps 3-7: process one audit task at a time ---
    for task_key in prompt_builder.task_keys():      # loop over the task names
        print(f"\n[*] Task '{task_key}': requesting audit script from local LLM...")

        # A NESTED FUNCTION (a "closure"): it can see `profile` from the enclosing scope.
        # WHY (logic): we pass this as a callback into the validator, which calls it once per attempt.
        # SUBTLE SYNTAX: `_task_key=task_key` binds the CURRENT loop value as a default argument.
        # Without this trick, the closure would read `task_key` LATE and every call would use the
        # loop's FINAL value - a classic Python "late binding in loops" bug. The default captures it now.
        def generate(feedback, _task_key=task_key):
            system_prompt, user_prompt = prompt_builder.build_task_prompt(
                profile, _task_key, feedback=feedback
            )
            if feedback:                             # truthy only on a retry
                print(f"    retrying '{_task_key}' with validator feedback...")
            # Return the prompts plus the LLM's reply, packaged in one dict for the validator.
            return {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "ai_response": ai_client.send(system_prompt, user_prompt),
            }

        # The validator drives generate -> validate -> retry and returns a single outcome dict.
        outcome = validator.validate_with_retries(generate)

        # Record this task. "completed" if approved else "failed_validation" is a TERNARY expression.
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

        # If it never passed validation, log why and SKIP execution (the security guarantee).
        if not outcome["approved"]:
            print(f"[!] Task '{task_key}' could not pass validation after "
                  f"{outcome['attempts']} attempt(s); skipping execution.")
            for issue in outcome["validation"]["issues"]:
                print(f"    - {issue}")
            audit_data["tasks"].append(task_result)  # still record the failed task for the report
            continue                                 # `continue` jumps to the next loop iteration

        # Approved: upload + run the script on the target, capture its output.
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
        # Parse the script's JSON output into structured findings/CVEs.
        task_result["findings"] = report_writer.extract_findings(script_output)
        task_result["cves"] = report_writer.extract_cves(script_output)

        # list.extend(other_list) appends ALL items of the other list (vs .append, which adds one
        # item). WHY: we're merging this task's findings into the running totals.
        audit_data["findings"].extend(task_result["findings"])
        audit_data["cves"].extend(task_result["cves"])
        audit_data["tasks"].append(task_result)      # store this task's full record

    # --- Step 8: persist the run log (JSON) and each generated script to disk ---
    log_path = report_writer.save_run_log(audit_data)
    script_paths = report_writer.save_generated_scripts(audit_data)
    print(f"\n[*] Run log saved to: {log_path}")
    print(f"[*] Saved {len(script_paths)} generated script(s) to generated_scripts/")

    # --- Step 9: build the final PDF report ---
    report_writer.write_pdf_report(audit_data, args.output)

    # --- Step 10: print a short console summary ---
    tasks = audit_data["tasks"]
    # sum(1 for t in tasks if ...) is a GENERATOR EXPRESSION feeding sum(): it yields a 1 for each
    # task whose status is "completed", and sum adds them - a concise way to COUNT matching items.
    completed = sum(1 for t in tasks if t["status"] == "completed")
    incomplete = len(tasks) - completed
    print("\n[+] Audit complete.")
    print(f"    Target   : {args.target}")
    print(f"    OS       : {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})")
    # The (f"..." if incomplete else "") appends extra text ONLY when some tasks failed (a ternary).
    print(f"    Tasks    : {completed}/{len(tasks)} completed"
          + (f", {incomplete} could not be completed" if incomplete else ""))
    print(f"    Findings : {len(audit_data['findings'])}")
    print(f"    CVEs     : {len(audit_data['cves'])}")
    print(f"[*] PDF report saved to: {args.output}")


# `__name__` is a special variable Python sets to "__main__" when a file is RUN DIRECTLY, but to
# the module's name when it is IMPORTED. So this block runs only for `python main.py`, not on import.
# WHY: it lets a file be both an executable program and an importable module.
if __name__ == "__main__":
    # try/except at the OUTERMOST level is a safety net: if anything inside main() raises (failed
    # SSH, unreachable LLM, ...), we convert it into a clean error message + failure exit code
    # instead of dumping a raw traceback.
    try:
        main()
    except Exception as error:           # `Exception` catches all normal runtime errors; `as error` names it
        # [REQUIREMENT: Module sys] report on stderr, exit non-zero so callers know it failed.
        print(f"[FATAL] Audit aborted: {error}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)                          # reached only on a clean run; exit code 0 = success
