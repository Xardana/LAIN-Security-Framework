import argparse
import os

import target_connector
import system_profile
import prompt_builder
import ai_client
import validator
import report_writer


def parse_args():
    parser = argparse.ArgumentParser(
        description="Defensive AI Audit Framework - runs on controller, audits remote targets over SSH"
    )
    parser.add_argument("--target", required=True, help="Target machine IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username on target machine")
    parser.add_argument("--key", default=None, help="Path to SSH private key file (optional)")
    parser.add_argument("--output", default="reports/audit_report.pdf", help="Path for the final PDF report")
    return parser.parse_args()


def main():
    args = parse_args()

    # Auth is agent-first (ssh-agent / Pageant) by default; --key and
    # SSH_PASSWORD are optional fallbacks for machines without agent access.
    ssh_password = os.environ.get("SSH_PASSWORD")

    print(f"[*] Starting audit of target: {args.target}")

    # Step 1: SSH into target and collect raw system information
    raw_data = target_connector.collect_system_info(
        host=args.target,
        username=args.user,
        key_path=args.key,
        password=ssh_password,
    )

    # Step 2: Parse raw remote data into a structured profile. This also
    # decides the target platform (linux/windows), which drives OS-correct
    # prompt selection below.
    profile = system_profile.parse(raw_data)
    print(f"[*] System profile collected: {profile.get('os', 'unknown')} "
          f"/ {profile.get('arch', 'unknown')} ({profile.get('platform', 'unknown')})")

    audit_data = {
        "target": args.target,
        "profile": profile,
        "tasks": [],
        "findings": [],
        "cves": [],
    }

    # Step 3-7: Audit one small, OS-specific task at a time. Each chunk is sent
    # to the local LLM and must pass the validator before it ever runs on the
    # target. If it fails, the validator asks the model to try again (up to its
    # max); if all attempts fail, the task is recorded as not completed so the
    # report shows why instead of leaving a blank section.
    for task_key in prompt_builder.task_keys():
        print(f"\n[*] Task '{task_key}': requesting audit script from local LLM...")

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

        outcome = validator.validate_with_retries(generate)

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

        if not outcome["approved"]:
            print(f"[!] Task '{task_key}' could not pass validation after "
                  f"{outcome['attempts']} attempt(s); skipping execution.")
            for issue in outcome["validation"]["issues"]:
                print(f"    - {issue}")
            audit_data["tasks"].append(task_result)
            continue

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

        audit_data["findings"].extend(task_result["findings"])
        audit_data["cves"].extend(task_result["cves"])
        audit_data["tasks"].append(task_result)

    # Step 8: Persist artifacts for auditability and manual review - a JSON log
    # of everything collected and generated, plus each generated script on disk.
    log_path = report_writer.save_run_log(audit_data)
    script_paths = report_writer.save_generated_scripts(audit_data)
    print(f"\n[*] Run log saved to: {log_path}")
    print(f"[*] Saved {len(script_paths)} generated script(s) to generated_scripts/")

    # Step 9: Generate the final PDF report with full pagination, findings, and CVEs
    report_writer.write_pdf_report(audit_data, args.output)

    # Step 10: Print summary
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
    main()
