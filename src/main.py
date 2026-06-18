import argparse
import os
import sys

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

    ssh_password = os.environ.get("SSH_PASSWORD")
    if not args.key and not ssh_password:
        print("[ERROR] Provide an SSH key via --key or set SSH_PASSWORD environment variable.")
        sys.exit(1)

    print(f"[*] Starting audit of target: {args.target}")

    # Step 1: SSH into target and collect raw system information
    raw_data = target_connector.collect_system_info(
        host=args.target,
        username=args.user,
        key_path=args.key,
        password=ssh_password,
    )

    # Step 2: Parse raw remote data into a structured profile
    profile = system_profile.parse(raw_data)
    print(f"[*] System profile collected: {profile.get('os', 'unknown')} / {profile.get('arch', 'unknown')}")

    # Step 3: Build prompts from the structured profile
    system_prompt, user_prompt = prompt_builder.build(profile)

    # Step 4: Send prompts to local LLM API and receive generated script
    print("[*] Sending profile to local LLM API...")
    ai_response = ai_client.send(system_prompt, user_prompt)

    # Step 5: Validate the generated script before any execution
    print("[*] Validating generated script...")
    validation_result = validator.validate(ai_response.get("script", ""))

    audit_data = {
        "target": args.target,
        "profile": profile,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "ai_response": ai_response,
        "validation": validation_result,
        "findings": [],
        "cves": [],
        "script_output": None,
    }

    if not validation_result["approved"]:
        print("[!] Script rejected by validator.")
        for issue in validation_result["issues"]:
            print(f"    - {issue}")
        report_writer.write_pdf_report(audit_data, args.output)
        print(f"[*] Rejection logged. PDF report saved to {args.output}")
        sys.exit(0)

    print("[*] Script approved. Executing on target...")

    # Step 6: Transfer and execute the validated script on the target
    script_output = target_connector.execute_script(
        host=args.target,
        username=args.user,
        key_path=args.key,
        password=ssh_password,
        script=ai_response["script"],
    )
    audit_data["script_output"] = script_output

    # Step 7: Extract structured findings and any referenced CVEs from script output
    audit_data["findings"] = report_writer.extract_findings(script_output)
    audit_data["cves"] = report_writer.extract_cves(script_output)

    # Step 8: Generate the final PDF report with full pagination, findings, and CVEs
    report_writer.write_pdf_report(audit_data, args.output)

    # Step 9: Print summary
    print("\n[+] Audit complete.")
    print(f"    Target  : {args.target}")
    print(f"    OS      : {profile.get('os', 'unknown')}")
    print(f"    Findings: {len(audit_data['findings'])}")
    print(f"    CVEs    : {len(audit_data['cves'])}")
    print(f"[*] PDF report saved to: {args.output}")


if __name__ == "__main__":
    main()
