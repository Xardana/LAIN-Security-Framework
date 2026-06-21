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
    # to the local LLM, validated, and only executed on the target if approved.
    # Keeping requests per-task keeps each prompt small enough for the 8B model.
    for task_key, system_prompt, user_prompt in prompt_builder.iter_task_prompts(profile):
        print(f"\n[*] Task '{task_key}': requesting audit script from local LLM...")
        ai_response = ai_client.send(system_prompt, user_prompt)

        validation_result = validator.validate(ai_response.get("script", ""))
        task_result = {
            "task": task_key,
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "ai_response": ai_response,
            "validation": validation_result,
            "script_output": None,
            "findings": [],
            "cves": [],
        }

        if not validation_result["approved"]:
            print(f"[!] Task '{task_key}' script rejected by validator.")
            for issue in validation_result["issues"]:
                print(f"    - {issue}")
            audit_data["tasks"].append(task_result)
            continue

        print(f"[*] Task '{task_key}' script approved. Executing on target...")
        script_output = target_connector.execute_script(
            host=args.target,
            username=args.user,
            script=ai_response["script"],
            key_path=args.key,
            password=ssh_password,
        )
        task_result["script_output"] = script_output
        task_result["findings"] = report_writer.extract_findings(script_output)
        task_result["cves"] = report_writer.extract_cves(script_output)

        audit_data["findings"].extend(task_result["findings"])
        audit_data["cves"].extend(task_result["cves"])
        audit_data["tasks"].append(task_result)

    # Step 8: Generate the final PDF report with full pagination, findings, and CVEs
    report_writer.write_pdf_report(audit_data, args.output)

    # Step 9: Print summary
    approved = sum(1 for t in audit_data["tasks"] if t["validation"]["approved"])
    print("\n[+] Audit complete.")
    print(f"    Target   : {args.target}")
    print(f"    OS       : {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})")
    print(f"    Tasks    : {approved}/{len(audit_data['tasks'])} approved & run")
    print(f"    Findings : {len(audit_data['findings'])}")
    print(f"    CVEs     : {len(audit_data['cves'])}")
    print(f"[*] PDF report saved to: {args.output}")


if __name__ == "__main__":
    main()
