"""
This file reads each task's results, builds the PDF report, and saves the run log. It's
the only file that knows anything about PDF formatting or writing files, so the rest of
the program doesn't have to. It just hands this file a finished bundle of results.
"""

import json                              # reads and writes JSON text.
import os                                # [REQUIREMENT: Module os] building paths + making directories.
import re                                # used to spot CVE ids and clean up filenames.
from datetime import datetime, timezone  # just the pieces we need out of the datetime module.

from fpdf import FPDF                     # the PDF-writing toolkit. We build on top of it below.
from fpdf.enums import XPos, YPos         # tell fpdf where to put the cursor after writing text.

# The severity levels, worst to least.
SEVERITIES = ("critical", "high", "medium", "low", "info")
# Each severity mapped to a rank (0 = worst), so we can sort findings by seriousness.
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}
# Each severity mapped to a color (red, green, blue) for its badge in the PDF.
SEVERITY_RGB = {
    "critical": (138, 11, 11),
    "high": (191, 54, 12),
    "medium": (191, 130, 0),
    "low": (33, 102, 33),
    "info": (60, 80, 110),
}
# Recognises CVE ids like "CVE-2024-12345", ignoring case.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# [REQUIREMENT: Functions] The helpers below are each a small piece we can test on its
# own. They pull findings and CVE ids out of a task's output.

def _coerce_output(script_output):
    """Whatever we were handed, a dict with "output"/"errors", a plain string, or
    nothing, turn it into one block of text, so everything below only has to deal with
    one kind of input."""
    if not script_output:                       # nothing there at all
        return ""
    if isinstance(script_output, dict):
        return script_output.get("output", "") or ""   # grab the printed text, or "" if missing
    return str(script_output)                   # [REQUIREMENT: Casting] fall back to plain text


def _load_json(text):
    """Try to read the text as JSON. If it won't, hand back nothing instead of crashing,
    so the caller can decide what to do next."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)                 # try the whole thing as JSON
    except json.JSONDecodeError:
        pass                                    # didn't work, try the fallback below
    # Sometimes the AI wraps its JSON in extra chatter. Find the first "{" and last "}"
    # and try reading just the bit between them.
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:                        # found both, in the right order?
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _normalize_finding(finding):
    """Take one finding from the AI and make sure it has exactly the fields the PDF
    wants, filling in safe defaults for anything missing. This way a messy or half-formed
    reply can never break the report."""
    severity = str(finding.get("severity", "info")).strip().lower()  # [REQUIREMENT: Casting]
    if severity not in SEVERITY_RANK:           # not one of our known levels?
        severity = "info"                       # just treat it as informational
    cves = finding.get("cves") or []            # missing/empty -> empty list
    if isinstance(cves, str):                   # AI gave one CVE as plain text instead of a list?
        cves = [cves]                           # wrap it so we handle it the same way
    return {
        "title": str(finding.get("title", "Untitled finding")).strip(),
        "severity": severity,
        "detail": str(finding.get("detail", "")).strip(),
        "evidence": str(finding.get("evidence", "")).strip(),
        # Keep only the ids that really look like CVEs, upper-cased, de-duplicated, sorted.
        "cves": sorted({c.upper() for c in cves if CVE_RE.fullmatch(str(c).strip())}),
    }


def normalize_findings(raw_findings):
    """Clean a list of finding dicts into the exact shape the report expects. The
    interpretation path hands us findings directly (the AI already returned them as
    data), so this is the shared entry point both paths use to make sure every finding
    has the right fields and safe defaults."""
    return [_normalize_finding(f) for f in (raw_findings or []) if isinstance(f, dict)]


def extract_findings(script_output):
    """Pull the findings out of one task's output. Used by the older path, where the
    findings arrive as text a script printed rather than as data."""
    text = _coerce_output(script_output)        # get the plain text
    data = _load_json(text)                     # try to read it as JSON
    if data is None:                            # couldn't read it as JSON
        if not text.strip():                    # and there was no output at all
            return []                           # so there's genuinely nothing to report
        # There was output, just not valid JSON. Rather than bin it, show it to a person
        # as a low-priority note so nothing gets silently lost.
        return [_normalize_finding({
            "title": "Unparsed audit output",
            "severity": "info",
            "detail": "Script output was not valid JSON matching the schema.",
            "evidence": text[:2000],
        })]
    # Got JSON. Grab the findings list (if it's there) and clean up each one.
    raw_findings = data.get("findings", []) if isinstance(data, dict) else []
    return normalize_findings(raw_findings)


def extract_cves(script_output):
    """Collect every CVE id this task mentioned, no duplicates."""
    cves = set()                                # a set drops duplicate ids for us
    for finding in extract_findings(script_output):
        cves.update(finding["cves"])            # add this finding's CVE ids
    # In case the AI mentioned a CVE outside the normal "cves" field, scan the raw text too.
    cves.update(m.upper() for m in CVE_RE.findall(_coerce_output(script_output)))
    return sorted(cves)                         # a consistent, sorted list


def _safe(text):
    """The PDF's built-in fonts only handle a limited set of characters, so this swaps
    anything unsupported for a "?" instead of letting the program crash."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


# [REQUIREMENT: Classes] _AuditPDF builds on top of fpdf's own PDF class, so it inherits
# all of fpdf's PDF-writing abilities for free. On top of that we add our own header,
# footer, and a handful of helper methods (h1, kv, ...) so every part of the report looks
# consistent.
class _AuditPDF(FPDF):
    def __init__(self):
        # Runs when we make a new _AuditPDF. Let fpdf set itself up first.
        super().__init__()
        self.set_auto_page_break(auto=True, margin=18)   # start new pages automatically, with a margin
        self.set_title("Defensive AI Audit Report")      # the PDF's title
        self._on_cover = False                  # True only while we're drawing the cover page

    def header(self):
        # fpdf calls this at the top of every page. Skip it on the cover.
        if self._on_cover:
            return                              # nothing on the cover page
        self.set_font("Helvetica", "I", 8)      # font, italic, small
        self.set_text_color(120, 120, 120)      # grey
        self.cell(0, 8, "Defensive AI Audit Report", align="L")   # title on the left
        self.cell(0, 8, self._title_target, align="R",            # target name on the right
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)            # then next line
        self.set_draw_color(200, 200, 200)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())  # a thin divider
        self.ln(4)                              # a bit of space

    def footer(self):
        # fpdf calls this at the bottom of every page.
        self.set_y(-15)                         # 15mm up from the bottom
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        # Prints "Page 1/5" and lets fpdf fill in the total page count.
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    # Small reusable drawing helpers, used by the render functions below.

    def h1(self, text):
        # A big page title.
        self.set_font("Helvetica", "B", 16)     # bold
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 9, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def h2(self, text):
        # A section heading with a line under it.
        self.ln(2)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(30, 50, 80)
        self.multi_cell(0, 7, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(210, 210, 210)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def kv(self, label, value):
        # One "Label:  value" row (used in the system-profile section).
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(40, 40, 40)
        self.cell(45, 6, _safe(label), new_x=XPos.RIGHT, new_y=YPos.TOP)   # fixed-width label
        self.set_font("Helvetica", "", 10)      # regular weight
        self.set_text_color(20, 20, 20)
        # Show a dash instead of blank space if the value is empty or missing.
        self.multi_cell(0, 6, _safe(value if value not in (None, "") else "-"),
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def body(self, text, size=10):
        # A normal paragraph.
        self.set_font("Helvetica", "", size)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 5.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def mono(self, text, size=8):
        # A fixed-width block (for prompts/JSON) so it stays neatly lined up.
        self.set_font("Courier", "", size)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 4.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def severity_chip(self, severity):
        # A small colored badge showing a finding's severity.
        r, g, b = SEVERITY_RGB.get(severity, SEVERITY_RGB["info"])
        self.set_fill_color(r, g, b)            # badge background color
        self.set_text_color(255, 255, 255)      # white text on top
        self.set_font("Helvetica", "B", 8)
        self.cell(24, 5, _safe(severity.upper()), align="C", fill=True,  # [REQUIREMENT: Casting]
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(20, 20, 20)         # reset the color for whatever comes next


def _severity_counts(findings):
    """Count how many findings land in each severity level, for the summary."""
    counts = {name: 0 for name in SEVERITIES}   # every level starts at 0
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return counts


def _render_cover(pdf, audit_data):
    """Draw the title page. We flip a flag so the header stays blank here."""
    pdf._on_cover = True
    pdf.add_page()                              # fresh page
    pdf.ln(40)                                  # push the title down a bit
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(20, 20, 20)
    pdf.multi_cell(0, 12, "Defensive AI Audit Report", align="C",
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)
    profile = audit_data.get("profile", {})     # the profile dict, or empty if there isn't one
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")  # a readable timestamp
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(60, 60, 60)
    # A short centered line for each of these.
    for line in (
        f"Target: {audit_data.get('target', 'unknown')}",
        f"OS: {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})",
        f"Generated: {generated}",
    ):
        pdf.multi_cell(0, 8, _safe(line), align="C",
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf._on_cover = False                        # cover done, normal headers resume


def _render_profile(pdf, profile):
    """Show every piece of collected system info as a label/value row."""
    pdf.add_page()
    pdf._title_target = _safe(profile.get("os", ""))   # sets the running header text for this section
    pdf.h1("System Profile")
    # Print a row for each (label, key) pair.
    for label, key in (
        ("Platform", "platform"), ("OS", "os"), ("OS release", "os_release"),
        ("Architecture", "arch"), ("Python", "python_version"),
        ("Privilege", "privilege"), ("CPU", "cpu"), ("Memory", "memory"),
    ):
        pdf.kv(label, profile.get(key, "-"))
    tools = profile.get("tools") or []          # list of tool names, or empty
    pdf.kv("Tools", ", ".join(tools) if tools else "-")
    network = profile.get("network") or []
    pdf.kv("Network", ", ".join(network) if network else "-")
    packages = profile.get("packages") or []
    if packages:
        pdf.kv("Python packages", f"{len(packages)} installed: " + ", ".join(packages))
    else:
        pdf.kv("Python packages", "-")


def _render_summary(pdf, audit_data):
    """A quick at-a-glance summary before the detailed task sections."""
    findings = audit_data.get("findings", [])
    tasks = audit_data.get("tasks", [])
    completed = sum(1 for t in tasks if t.get("status") == "completed")   # count completed tasks
    incomplete = len(tasks) - completed
    counts = _severity_counts(findings)

    pdf.h2("Summary")
    depth = audit_data.get("depth")
    if depth:
        # Show how thorough this run was, since it adapts to the target's resources.
        pdf.kv("Audit depth", depth)
    pdf.kv("Tasks completed", f"{completed} of {len(tasks)} attempted")
    if incomplete:                              # only show this row if some tasks failed
        pdf.kv("Not completed", f"{incomplete} (failed safety validation; see task sections)")
    pdf.kv("Total findings", str(len(findings)))  # [REQUIREMENT: Casting]
    # Build a line like "critical=1  high=2 ..." from the counts.
    pdf.kv("By severity", "  ".join(f"{s}={counts[s]}" for s in SEVERITIES))
    pdf.kv("CVEs referenced", str(len(audit_data.get("cves", []))))


def _render_task(pdf, task):
    """Draw one task section: either its findings, or a clear "NOT COMPLETED" note, so a
    failed task is never just left silently blank."""
    name = task.get("task", "unnamed task")
    validation = task.get("validation", {}) or {}
    completed = task.get("status") == "completed"
    attempts = task.get("attempts", 1)
    pdf.h2(f"Task: {name}")

    if not completed:
        pdf.set_text_color(150, 30, 30)         # red, to draw the eye
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 6, _safe("NOT COMPLETED"),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(20, 20, 20)
        pdf.body(
            f"The AI-generated script failed safety validation on all "
            f"{attempts} attempt(s), so it was never executed on the target. "
            f"Validator objections from the final attempt:"
        )
        for issue in validation.get("issues", []):
            pdf.body(f"  - {issue}")
        return                                  # nothing more to show for a failed task

    findings = task.get("findings", [])
    pdf.body(f"Status: completed on attempt {attempts}. {len(findings)} finding(s).")

    # If the collector couldn't check something (usually because it needed root), say so
    # plainly. This is the honest replacement for the old habit of turning a failed
    # command into a fake finding, the gap gets reported as a gap.
    facts = task.get("collected_facts") or {}
    gaps = facts.get("errors") or []
    if gaps:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(120, 90, 30)
        pdf.multi_cell(0, 5, _safe("Coverage gaps (could not be checked): " + "; ".join(gaps)),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(20, 20, 20)
    pdf.ln(1)

    if not findings:                            # completed, but nothing worth flagging
        pdf.body("No notable findings reported for this task.")
        return

    # Most severe findings first.
    for finding in sorted(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99)):
        pdf.severity_chip(finding["severity"])  # colored badge
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 6, _safe(finding["title"]),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if finding["detail"]:                   # only print fields that have something in them
            pdf.body(finding["detail"])
        if finding["evidence"]:
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(90, 90, 90)
            pdf.multi_cell(0, 4.5, _safe("Evidence: " + finding["evidence"]),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if finding["cves"]:
            pdf.body("CVEs: " + ", ".join(finding["cves"]), size=9)
        pdf.ln(2)                               # space before the next finding


def _render_cves(pdf, audit_data):
    """One combined list of every CVE mentioned across all tasks."""
    cves = audit_data.get("cves", [])
    pdf.h2("Referenced CVEs")
    if not cves:                                # nothing to list
        pdf.body("No CVEs were referenced by any task.")
        return
    for cve in cves:
        pdf.body(f"- {cve}")


def _render_appendix(pdf, audit_data):
    """The full detail behind every task: the exact prompts, the raw AI reply, the
    validation result, and the facts, so a reviewer can double-check exactly what was
    sent and received."""
    pdf.add_page()
    pdf.h1("Appendix: Prompts, Responses & Raw Output")
    for task in audit_data.get("tasks", []):
        pdf.h2(f"Task: {task.get('task', 'unnamed')}")
        pdf.body("System prompt:", size=9)
        pdf.mono(task.get("system_prompt", ""))
        pdf.body("User prompt:", size=9)
        pdf.mono(task.get("user_prompt", ""))
        pdf.body("AI response (raw):", size=9)
        # Pretty-print the reply as readable JSON, capped so one huge reply can't bloat
        # the whole report.
        pdf.mono(json.dumps(task.get("ai_response", {}), indent=2)[:6000])
        pdf.body("Validation:", size=9)
        pdf.mono(json.dumps(task.get("validation", {}), indent=2)[:3000])
        # The interpretation path records the exact facts each finding was based on.
        # Showing them here is what lets a reviewer trace every finding back to real
        # collected data, which is the whole point of the new approach.
        facts = task.get("collected_facts")
        if facts is not None:
            pdf.body("Collected facts (what the findings are based on):", size=9)
            pdf.mono(json.dumps(facts, indent=2)[:6000])
        output = task.get("script_output")
        if output is not None:                  # only there on the older script-based path
            pdf.body("Raw script output:", size=9)
            pdf.mono(json.dumps(output, indent=2)[:6000])


def write_pdf_report(audit_data, output_path):
    """The main way in for building the PDF. Builds the document section by section, then
    saves it to disk."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)  # [REQUIREMENT: Module os]

    pdf = _AuditPDF()                           # fresh PDF document
    pdf._title_target = _safe(audit_data.get("target", ""))   # header text shown on every page
    pdf.alias_nb_pages()                        # lets the footer show the right total page count

    # Build the report section by section, in order.
    _render_cover(pdf, audit_data)
    _render_profile(pdf, audit_data.get("profile", {}))
    _render_summary(pdf, audit_data)
    for task in audit_data.get("tasks", []):    # one section per task
        _render_task(pdf, task)
    _render_cves(pdf, audit_data)
    _render_appendix(pdf, audit_data)

    pdf.output(output_path)                     # save the finished document
    return output_path


# Below here is the logging and saving of files.


def _slug(value):
    """Make any value safe to drop in a filename, by turning anything that isn't a
    letter, digit, dot, underscore, or hyphen into an underscore."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value)) or "target"  # [REQUIREMENT: Casting]


def _timestamp():
    """A compact, sortable timestamp like "20260621T035420Z" that's also safe in a filename."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def save_run_log(audit_data, log_dir="logs"):
    """Save a full JSON record of the whole run, the profile, every prompt, every reply,
    every validation result, every output, as the audit trail."""
    os.makedirs(log_dir, exist_ok=True)         # [REQUIREMENT: Module os] make sure logs/ exists
    path = os.path.join(
        log_dir, f"audit_{_slug(audit_data.get('target'))}_{_timestamp()}.json")
    # [REQUIREMENT: File handling] open the file for writing, and it closes itself afterward.
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(audit_data, handle, indent=2, default=str)
    return path                                 # tell the caller where we saved it


def save_generated_scripts(audit_data, scripts_dir="generated_scripts"):
    """Save each AI-generated script as its own .py file, so a person can review them
    later. Only the older script path produces these; the interpretation path doesn't."""
    os.makedirs(scripts_dir, exist_ok=True)     # [REQUIREMENT: Module os] make sure the folder exists
    timestamp = _timestamp()                    # one shared timestamp for the whole batch
    saved = []                                  # the paths we wrote, to hand back to the caller
    for task in audit_data.get("tasks", []):
        script = (task.get("ai_response") or {}).get("script")  # the script text, if any
        if not script:                          # nothing to save for this task
            continue
        # A filename showing the task name and whether it passed, so failed scripts stand out.
        name = f"{_slug(task.get('task'))}_{task.get('status', 'unknown')}_{timestamp}.py"
        path = os.path.join(scripts_dir, name)
        # [REQUIREMENT: File handling] write the script text to its own file.
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        saved.append(path)
    return saved                                # list of files written
