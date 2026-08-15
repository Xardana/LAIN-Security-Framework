"""
main.py is the starting point of the program. It doesn't do much work itself -
instead it calls the other files in the right order, kind of like a recipe that
tells each helper when to do its job.

How the audit now works (Phase 3)
---------------------------------
The earlier version asked the AI to write a script for each check, validated the
script, ran it on the target, and read whatever it printed. Testing showed the
scripts were safe but frequently wrong: they misread command output, and two
runs of the same audit disagreed with each other.

So the flow changed. Now our own code (collectors.py) gathers the raw facts
using fixed, read-only commands, and the AI's only job is to look at those facts
and decide what is worth reporting. The facts are identical every run, so the
findings stop drifting, and the AI is doing the part it is actually good at -
judgement, not parsing.

  collect profile -> run collector commands -> parse facts -> AI interprets facts -> report
"""

import argparse   # a library that reads the options typed on the command line.
import os          # [REQUIREMENT: Module os] os.environ reads the optional SSH password.
import sys         # [REQUIREMENT: Module sys] sys.exit (process exit codes) + sys.stderr (error stream).

# Bring in the helper files. Each one has one job.
import target_connector   # SSH: read info from the target and run our collector commands
import system_profile     # parse raw output into a clean profile dict
import collectors         # our own deterministic fact-gathering (replaces AI-written scripts)
import prompt_builder     # build the LLM prompts
import ai_client          # send prompts to the LLM
import report_writer      # save logs + write the PDF


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


def _findings_from_reply(reply):
    """Pull the list of findings out of the AI's interpretation reply, being
    forgiving about the exact shape it comes back in. A well-behaved reply is
    {"task": ..., "findings": [...]}, but we also accept a bare list, and treat
    anything else as "no findings" rather than crashing."""
    if isinstance(reply, dict) and isinstance(reply.get("findings"), list):
        return reply["findings"]
    if isinstance(reply, list):
        return reply
    return []


def _interpret_one(profile, name, result):
    """Ask the AI to interpret one collector's facts, and package the outcome in
    the shape report_writer expects. Kept as its own function so a failure to
    interpret one check (say the AI call times out) records that cleanly and the
    rest of the audit carries on."""
    system_prompt, user_prompt = prompt_builder.build_interpretation_prompt(profile, name, result)
    try:
        reply = ai_client.send(system_prompt, user_prompt)
        findings = report_writer.normalize_findings(_findings_from_reply(reply))
        status = "completed"
        # Carry any coverage gaps the collector reported through to the report.
        validation = {"approved": True, "issues": result.get("errors", []), "warnings": []}
    except Exception as error:
        """One interpretation failing shouldn't sink the whole run. We record it as
        a not-completed task with the reason, and keep going."""
        reply = {"error": str(error)}
        findings = []
        status = "failed_interpretation"
        validation = {"approved": False, "issues": [f"AI interpretation failed: {error}"], "warnings": []}

    # CVE ids gathered from this check's findings, de-duplicated and sorted.
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
        """If something goes wrong, we want the program to clearly say so and exit
        with an error status, so anything watching this program knows the run failed."""
        print("[ERROR] No system information collected from target.", file=sys.stderr)
        sys.exit(1)

    # --- Step 2: Parse the raw output into a structured profile dict ---
    profile = system_profile.parse(raw_data)         # also figures out linux vs windows
    print(f"[*] System profile collected: {profile.get('os', 'unknown')} "
          f"/ {profile.get('arch', 'unknown')} ({profile.get('platform', 'unknown')})")

    """This is where we build up everything we've learned during the audit, so we
    can hand it all to the report writer at the end."""
    audit_data = {
        "target": args.target,
        "profile": profile,
        "tasks": [],
        "findings": [],
        "cves": [],
    }

    # --- Step 3: pick the collectors that suit this machine's operating system ---
    platform = profile.get("platform", "linux")
    active_collectors = collectors.for_platform(platform)

    if not active_collectors:
        """We don't have collectors for this OS yet (Windows is still to come). We
        still write a report so there's an artifact showing what was and wasn't done,
        rather than failing silently."""
        print(f"[!] No collectors available for platform '{platform}' yet; "
              f"the profile was captured but no checks were run.")
    else:
        # --- Step 4: run every collector's commands over ONE SSH connection ---
        commands = collectors.all_commands(active_collectors)
        print(f"[*] Collecting facts over SSH ({len(active_collectors)} checks, "
              f"{len(commands)} commands)...")
        outputs = target_connector.run_commands(
            host=args.target,
            username=args.user,
            commands=commands,
            key_path=args.key,
            password=ssh_password,
        )

        # --- Step 5: parse the raw output into deterministic facts ---
        results = collectors.collect_all(active_collectors, outputs)

        # --- Step 6: have the AI interpret each check's facts into findings ---
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

    # Collapse any duplicate CVE ids across all the checks.
    audit_data["cves"] = sorted(set(audit_data["cves"]))

    # --- Step 7: persist the full run log (JSON) as the audit trail ---
    log_path = report_writer.save_run_log(audit_data)
    print(f"\n[*] Run log saved to: {log_path}")

    # --- Step 8: build the final PDF report ---
    report_writer.write_pdf_report(audit_data, args.output)

    # --- Step 9: print a short console summary ---
    tasks = audit_data["tasks"]
    completed = sum(1 for t in tasks if t["status"] == "completed")   # count how many checks finished
    incomplete = len(tasks) - completed
    print("\n[+] Audit complete.")
    print(f"    Target   : {args.target}")
    print(f"    OS       : {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})")
    print(f"    Checks   : {completed}/{len(tasks)} completed"
          + (f", {incomplete} could not be interpreted" if incomplete else ""))
    print(f"    Findings : {len(audit_data['findings'])}")
    print(f"    CVEs     : {len(audit_data['cves'])}")
    print(f"[*] PDF report saved to: {args.output}")


"""This last bit only runs when you launch this file directly (like typing
`python main.py`), not when some other file imports it. It's the program's
actual "on" switch."""
if __name__ == "__main__":
    """If anything goes wrong anywhere in main() - like the SSH connection failing
    or the AI being unreachable - we catch it here so the user gets a clean error
    message instead of a scary wall of technical text."""
    try:
        main()
    except Exception as error:           # catch any normal error and give it the name "error"
        # [REQUIREMENT: Module sys] report on stderr, exit non-zero so callers know it failed.
        print(f"[FATAL] Audit aborted: {error}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)                          # only reached if everything went fine; 0 means success
