"""
This is where the program starts. It doesn't do much itself, it just calls the other
files in the right order, like a recipe telling each helper when to do its bit.

How the audit works now (Phase 3):
The old version asked the AI to write a script for each check, validated it, ran it on
the target, and read what it printed. Testing showed those scripts were safe but often
wrong. They misread the command output, and two runs of the same audit disagreed with
each other.

So we changed the flow. Now our own code (collectors.py) gathers the raw facts with
fixed, read-only commands, and the AI's only job is to look at those facts and decide
what's worth reporting. The facts are identical every run, so the findings stop
drifting, and the AI does the part it's actually good at, which is judgement, not
parsing.

  collect profile -> run collector commands -> parse facts -> AI interprets -> report
"""

import argparse   # reads the options typed on the command line.
import os          # [REQUIREMENT: Module os] os.environ reads the optional SSH password.
import sys         # [REQUIREMENT: Module sys] sys.exit (exit codes) + sys.stderr (error stream).

# The helper files, one job each.
import target_connector   # SSH: read info off the target and run our collector commands
import system_profile     # turn raw output into a clean profile dict
import collectors         # our own fact-gathering that gives the same answer every time
import prompt_builder     # build the prompts
import ai_client          # send the prompts to the AI
import report_writer      # save logs and write the PDF


# [REQUIREMENT: Functions] The program is split into functions so "read the options"
# and "run the audit" each stay short and easy to follow.
def parse_args():
    """Set up the command-line options, like --target and --user, and say what each
    one is for."""
    parser = argparse.ArgumentParser(
        description="Defensive AI Audit Framework - runs on controller, audits remote targets over SSH"
    )
    parser.add_argument("--target", required=True, help="Target machine IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username on target machine")
    parser.add_argument("--key", default=None, help="Path to SSH private key file (optional)")
    parser.add_argument("--output", default="reports/audit_report.pdf", help="Path for the final PDF report")
    parser.add_argument(
        "--depth", choices=["auto", "lightweight", "detailed"], default="auto",
        help="How thorough to be. 'auto' (the default) decides from the target's own resources.",
    )
    # Read whatever was typed and hand back a neat object with each option on it.
    return parser.parse_args()


def _findings_from_reply(reply):
    """Pull the findings list out of the AI's reply, without being fussy about the
    exact shape. A tidy reply is {"task": ..., "findings": [...]}, but we also take a
    bare list, and treat anything else as "no findings" rather than crashing."""
    if isinstance(reply, dict) and isinstance(reply.get("findings"), list):
        return reply["findings"]
    if isinstance(reply, list):
        return reply
    return []


def _interpret_one(profile, name, result):
    """Ask the AI to interpret one collector's facts, and package the result in the
    shape report_writer wants. It's its own function so that if one check fails to
    interpret (say the AI call times out), we record that cleanly and the rest of the
    audit carries on."""
    system_prompt, user_prompt = prompt_builder.build_interpretation_prompt(profile, name, result)
    try:
        reply = ai_client.send(system_prompt, user_prompt)
        findings = report_writer.normalize_findings(_findings_from_reply(reply))
        status = "completed"
        # Carry any coverage gaps the collector reported through to the report.
        validation = {"approved": True, "issues": result.get("errors", []), "warnings": []}
    except Exception as error:
        # One check failing shouldn't sink the whole run. Record it as not-completed
        # with the reason, and keep going.
        reply = {"error": str(error)}
        findings = []
        status = "failed_interpretation"
        validation = {"approved": False, "issues": [f"AI interpretation failed: {error}"], "warnings": []}

    # CVE ids from this check's findings, de-duplicated and sorted.
    cves = sorted({cve for finding in findings for cve in finding["cves"]})

    return {
        "task": name,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "ai_response": reply,
        "collected_facts": result,        # the exact facts the findings are based on
        "validation": validation,
        "attempts": 1,
        "status": status,
        "findings": findings,
        "cves": cves,
    }


def main():
    args = parse_args()                              # here we go

    # Grab an optional password from the environment. If it's not set, this is just empty.
    ssh_password = os.environ.get("SSH_PASSWORD")

    print(f"[*] Starting audit of target: {args.target}")

    # Step 1: SSH in and collect raw, read-only system info.
    raw_data = target_connector.collect_system_info(
        host=args.target,
        username=args.user,
        key_path=args.key,
        password=ssh_password,
    )

    # Nothing came back means nothing to do, so stop here.
    if not raw_data:
        # Say so clearly and exit with an error status, so anything watching this
        # program knows the run failed.
        print("[ERROR] No system information collected from target.", file=sys.stderr)
        sys.exit(1)

    # Step 2: turn the raw output into a clean profile.
    profile = system_profile.parse(raw_data)         # also works out linux vs windows
    print(f"[*] System profile collected: {profile.get('os', 'unknown')} "
          f"/ {profile.get('arch', 'unknown')} ({profile.get('platform', 'unknown')})")

    # Decide how deep to go: use --depth if given, otherwise let the profile decide.
    depth = args.depth if args.depth != "auto" else collectors.resource_tier(profile)
    chosen_by = "set by --depth" if args.depth != "auto" else "chosen from target resources"
    print(f"[*] Audit depth: {depth} ({chosen_by})")

    # This is where we pile up everything we learn, to hand off to the report writer.
    audit_data = {
        "target": args.target,
        "profile": profile,
        "depth": depth,
        "tasks": [],
        "findings": [],
        "cves": [],
    }

    # Step 3: pick the collectors that suit this machine's OS.
    platform = profile.get("platform", "linux")
    active_collectors = collectors.for_platform(platform)

    if not active_collectors:
        # No collectors for this OS yet (Windows is still to come). We still write a
        # report so there's an artifact showing what did and didn't happen, rather than
        # failing quietly.
        print(f"[!] No collectors available for platform '{platform}' yet; "
              f"the profile was captured but no checks were run.")
    else:
        # Step 4: run every collector's commands (at the chosen depth) over ONE SSH connection.
        commands = collectors.all_commands(active_collectors, depth)
        print(f"[*] Collecting facts over SSH ({len(active_collectors)} checks, "
              f"{len(commands)} commands)...")
        outputs = target_connector.run_commands(
            host=args.target,
            username=args.user,
            commands=commands,
            key_path=args.key,
            password=ssh_password,
        )

        # Step 5: turn the raw output into deterministic facts.
        results = collectors.collect_all(active_collectors, outputs, depth)

        # Step 6: have the AI interpret each check's facts into findings.
        for name, result in results.items():
            fact_count = len(result.get("records", []))
            print(f"\n[*] Interpreting '{name}' ({fact_count} fact(s) collected)...")

            task_result = _interpret_one(profile, name, result)

            audit_data["findings"].extend(task_result["findings"])
            audit_data["cves"].extend(task_result["cves"])
            audit_data["tasks"].append(task_result)

            gap_note = (f", {len(result['errors'])} coverage gap(s)"
                        if result.get("errors") else "")
            if task_result["status"] == "completed":
                print(f"    -> {len(task_result['findings'])} finding(s){gap_note}")
            else:
                print(f"    -> interpretation failed: {task_result['validation']['issues'][0]}")

    # Fold together any duplicate CVE ids across all the checks.
    audit_data["cves"] = sorted(set(audit_data["cves"]))

    # Step 7: save the full run log (JSON) as the audit trail.
    log_path = report_writer.save_run_log(audit_data)
    print(f"\n[*] Run log saved to: {log_path}")

    # Step 8: build the PDF report.
    report_writer.write_pdf_report(audit_data, args.output)

    # Step 9: print a short summary to the console.
    tasks = audit_data["tasks"]
    completed = sum(1 for t in tasks if t["status"] == "completed")   # how many checks finished
    incomplete = len(tasks) - completed
    print("\n[+] Audit complete.")
    print(f"    Target   : {args.target}")
    print(f"    OS       : {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})")
    print(f"    Checks   : {completed}/{len(tasks)} completed"
          + (f", {incomplete} could not be interpreted" if incomplete else ""))
    print(f"    Findings : {len(audit_data['findings'])}")
    print(f"    CVEs     : {len(audit_data['cves'])}")
    print(f"[*] PDF report saved to: {args.output}")


# This only runs when you launch the file directly (python main.py), not when another
# file imports it. It's the actual on switch.
if __name__ == "__main__":
    # If anything blows up in main(), like the SSH connection failing or the AI being
    # unreachable, we catch it here so the user gets a clean message instead of a scary
    # wall of technical text.
    try:
        main()
    except Exception as error:           # catch any normal error, call it "error"
        # [REQUIREMENT: Module sys] report on stderr, exit non-zero so callers know it failed.
        print(f"[FATAL] Audit aborted: {error}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)                          # only reached if everything went fine; 0 means success
