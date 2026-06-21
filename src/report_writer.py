# report_writer.py - reads each task's JSON output, then produces the PDF report
# and saves the run log + generated scripts to disk.

import json                              # parse/serialise JSON (loads = text->obj, dump = obj->file)
import os                                # [REQUIREMENT: Module os] build paths, create folders
import re                                # regex: find CVE ids, sanitise filenames
from datetime import datetime, timezone  # build a UTC timestamp for the report/filenames

from fpdf import FPDF                     # the PDF engine; we subclass it below
from fpdf.enums import XPos, YPos         # constants telling fpdf where to move the cursor next

# Severity levels ordered worst -> least. A tuple is an immutable (unchangeable) list.
SEVERITIES = ("critical", "high", "medium", "low", "info")
# Build a {name: position} dict so we can sort findings by severity later.
# enumerate gives (index, value) pairs: (0,"critical"), (1,"high"), ...
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}   # dict comprehension
# A colour (Red, Green, Blue 0-255) for each severity's badge in the PDF.
SEVERITY_RGB = {
    "critical": (138, 11, 11),
    "high": (191, 54, 12),
    "medium": (191, 130, 0),
    "low": (33, 102, 33),
    "info": (60, 80, 110),
}
# A compiled regex matching a CVE id like "CVE-2021-44228". \d = a digit,
# {4} = exactly 4 of them, {4,7} = between 4 and 7. re.IGNORECASE = case-insensitive.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# --------------------------------------------------------------------------
# JSON extraction helpers (main.py calls extract_findings / extract_cves)
# [REQUIREMENT: Functions] each helper below is one small, testable function.
# --------------------------------------------------------------------------

def _coerce_output(script_output):
    # Return the stdout text no matter what shape the input has.
    if not script_output:                       # None or empty -> ""
        return ""
    if isinstance(script_output, dict):         # isinstance checks the type
        # target_connector returns {"output", "errors"}; grab "output" (or "" if missing).
        return script_output.get("output", "") or ""
    # [REQUIREMENT: Casting] anything else: cast it to a string as a safe fallback.
    return str(script_output)


def _load_json(text):
    # Try to turn text into a Python object (dict), or return None if impossible.
    text = text.strip()                         # remove surrounding whitespace
    if not text:                                # empty string -> nothing to parse
        return None
    try:
        return json.loads(text)                 # attempt: the whole thing is JSON
    except json.JSONDecodeError:                # not valid JSON
        pass                                    # fall through to the fallback below
    # Fallback: the model may have wrapped the JSON in prose. find/rfind get the
    # positions of the first "{" and last "}"; we try to parse just that slice.
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:                        # both found and in the right order
        try:
            return json.loads(text[start:end + 1])   # slice [start..end] inclusive
        except json.JSONDecodeError:
            return None
    return None


def _normalize_finding(finding):
    # Force one finding dict into the exact keys/shape the PDF expects.
    # [REQUIREMENT: Casting] str(...) lets .strip()/.lower() work even if the model
    # returned a number or None for severity.
    severity = str(finding.get("severity", "info")).strip().lower()
    if severity not in SEVERITY_RANK:           # unknown value -> default to "info"
        severity = "info"
    cves = finding.get("cves") or []            # missing/None -> empty list
    if isinstance(cves, str):                   # if the model gave a single string,
        cves = [cves]                           # wrap it in a list so we can loop it
    return {
        "title": str(finding.get("title", "Untitled finding")).strip(),
        "severity": severity,
        "detail": str(finding.get("detail", "")).strip(),
        "evidence": str(finding.get("evidence", "")).strip(),
        # Keep only strings that fully match the CVE pattern; upper-case + dedupe
        # them with a set comprehension, then sort. fullmatch = the WHOLE string matches.
        "cves": sorted({c.upper() for c in cves if CVE_RE.fullmatch(str(c).strip())}),
    }


def extract_findings(script_output):
    # Parse the standardized findings list out of one task's output.
    text = _coerce_output(script_output)        # get the stdout text
    data = _load_json(text)                     # try to parse it into a dict
    if data is None:                            # parsing failed
        if not text.strip():                    # ...and there was no output at all
            return []                           # -> no findings
        # There WAS output but it wasn't valid JSON: don't silently lose it,
        # surface it as a single low-priority "info" finding instead.
        return [_normalize_finding({
            "title": "Unparsed audit output",
            "severity": "info",
            "detail": "Script output was not valid JSON matching the schema.",
            "evidence": text[:2000],            # first 2000 chars, so the PDF stays sane
        })]
    # data parsed OK. Get its "findings" list (only if data is a dict), then
    # normalise each finding. The "if isinstance(f, dict)" skips malformed entries.
    raw_findings = data.get("findings", []) if isinstance(data, dict) else []
    return [_normalize_finding(f) for f in raw_findings if isinstance(f, dict)]


def extract_cves(script_output):
    # Collect every CVE id mentioned in this task's output.
    cves = set()                                # a set automatically de-duplicates
    for finding in extract_findings(script_output):
        cves.update(finding["cves"])            # add all of this finding's CVEs
    # Backstop: also scan the raw text for CVEs the model mentioned outside the field.
    cves.update(m.upper() for m in CVE_RE.findall(_coerce_output(script_output)))
    return sorted(cves)                         # return a sorted list


# --------------------------------------------------------------------------
# PDF template
# --------------------------------------------------------------------------

def _safe(text):
    # fpdf's built-in fonts only support Latin-1 characters. This converts the
    # text to Latin-1, replacing anything unsupported with "?", so writing never
    # crashes on an odd character. encode -> bytes, decode -> back to a clean str.
    return str(text).encode("latin-1", "replace").decode("latin-1")


# [REQUIREMENT: Classes] _AuditPDF is a CLASS that inherits from FPDF (the
# parentheses mean "subclass of FPDF"). Subclassing lets us override header()/
# footer() - which fpdf calls automatically on each page - and add our own helper
# methods (h1, h2, kv, ...) that the render functions reuse for one consistent look.
class _AuditPDF(FPDF):
    def __init__(self):
        # __init__ is the constructor; it runs when we create an _AuditPDF().
        super().__init__()                      # run FPDF's own constructor first
        self.set_auto_page_break(auto=True, margin=18)   # auto-add pages, keep an 18mm bottom margin
        self.set_title("Defensive AI Audit Report")      # PDF metadata title
        self._on_cover = False                  # flag: True only while drawing the cover page

    def header(self):
        # Called automatically at the TOP of every page. We skip it on the cover.
        if self._on_cover:
            return                              # draw nothing on the cover page
        self.set_font("Helvetica", "I", 8)      # font family, "I"=italic, size 8
        self.set_text_color(120, 120, 120)      # grey
        self.cell(0, 8, "Defensive AI Audit Report", align="L")   # left-aligned title
        self.cell(0, 8, self._title_target, align="R",            # right-aligned target name
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)            # then move to the next line
        self.set_draw_color(200, 200, 200)      # light grey for the rule line
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())  # horizontal line
        self.ln(4)                              # add 4mm vertical space

    def footer(self):
        # Called automatically at the BOTTOM of every page: print the page number.
        self.set_y(-15)                         # 15mm up from the bottom
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        # {nb} is replaced with the total page count (enabled by alias_nb_pages()).
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    # --- small reusable drawing helpers, used by the render functions below ---

    def h1(self, text):
        # A big page title.
        self.set_font("Helvetica", "B", 16)     # "B" = bold
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 9, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)  # wraps long text
        self.ln(1)

    def h2(self, text):
        # A section heading with an underline.
        self.ln(2)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(30, 50, 80)
        self.multi_cell(0, 7, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(210, 210, 210)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def kv(self, label, value):
        # One "Label: value" row (used for the system-profile table).
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(40, 40, 40)
        self.cell(45, 6, _safe(label), new_x=XPos.RIGHT, new_y=YPos.TOP)   # 45mm-wide label cell
        self.set_font("Helvetica", "", 10)      # "" = regular weight
        self.set_text_color(20, 20, 20)
        # If value is None or "", show "-" instead. multi_cell wraps long values.
        self.multi_cell(0, 6, _safe(value if value not in (None, "") else "-"),
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def body(self, text, size=10):
        # A normal wrapped paragraph. size defaults to 10 but callers can override.
        self.set_font("Helvetica", "", size)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 5.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def mono(self, text, size=8):
        # Monospaced block (Courier), used for prompts/JSON in the appendix.
        self.set_font("Courier", "", size)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 4.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def severity_chip(self, severity):
        # Draw a small coloured badge showing a finding's severity.
        # Tuple-unpacking: pull the three colour numbers out at once.
        r, g, b = SEVERITY_RGB.get(severity, SEVERITY_RGB["info"])
        self.set_fill_color(r, g, b)            # badge background colour
        self.set_text_color(255, 255, 255)      # white text
        self.set_font("Helvetica", "B", 8)
        # [REQUIREMENT: Casting] severity.upper() returns a new UPPER-CASE string.
        self.cell(24, 5, _safe(severity.upper()), align="C", fill=True,   # fill=True = paint the box
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(20, 20, 20)         # reset text colour for whatever comes next


def _severity_counts(findings):
    # Count how many findings fall into each severity bucket.
    counts = {name: 0 for name in SEVERITIES}   # start every bucket at 0
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1   # increment that bucket
    return counts


def _render_cover(pdf, audit_data):
    # Draw the title/cover page.
    pdf._on_cover = True                        # tell header() to stay blank here
    pdf.add_page()                              # start a new page
    pdf.ln(40)                                  # push the title down 40mm
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(20, 20, 20)
    pdf.multi_cell(0, 12, "Defensive AI Audit Report", align="C",
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)
    profile = audit_data.get("profile", {})     # the system profile (or {} if absent)
    # datetime.now(timezone.utc) = current UTC time; strftime formats it as text.
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(60, 60, 60)
    # Loop over three centred subtitle lines.
    for line in (
        f"Target: {audit_data.get('target', 'unknown')}",
        f"OS: {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})",
        f"Generated: {generated}",
    ):
        pdf.multi_cell(0, 8, _safe(line), align="C",
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf._on_cover = False                        # cover done; normal headers resume


def _render_profile(pdf, profile):
    # Draw the System Profile page: every piece of collected info as a kv row.
    pdf.add_page()
    pdf._title_target = _safe(profile.get("os", ""))   # set the running-header text
    pdf.h1("System Profile")
    # Loop over (display label, profile key) pairs and print each as a row.
    for label, key in (
        ("Platform", "platform"), ("OS", "os"), ("OS release", "os_release"),
        ("Architecture", "arch"), ("Python", "python_version"),
        ("Privilege", "privilege"), ("CPU", "cpu"), ("Memory", "memory"),
    ):
        pdf.kv(label, profile.get(key, "-"))
    tools = profile.get("tools") or []          # list of tool names (or empty)
    pdf.kv("Tools", ", ".join(tools) if tools else "-")     # join into one string
    network = profile.get("network") or []
    pdf.kv("Network", ", ".join(network) if network else "-")
    packages = profile.get("packages") or []
    if packages:
        # Show the count plus the full list. len() gives the number of packages.
        pdf.kv("Python packages", f"{len(packages)} installed: " + ", ".join(packages))
    else:
        pdf.kv("Python packages", "-")


def _render_summary(pdf, audit_data):
    # Draw the at-a-glance Summary block.
    findings = audit_data.get("findings", [])
    tasks = audit_data.get("tasks", [])
    completed = sum(1 for t in tasks if t.get("status") == "completed")   # count completed tasks
    incomplete = len(tasks) - completed
    counts = _severity_counts(findings)

    pdf.h2("Summary")
    pdf.kv("Tasks completed", f"{completed} of {len(tasks)} attempted")
    if incomplete:                              # only show this row if some tasks failed
        pdf.kv("Not completed", f"{incomplete} (failed safety validation; see task sections)")
    # [REQUIREMENT: Casting] str(len(...)) turns the integer count into text for the cell.
    pdf.kv("Total findings", str(len(findings)))
    # Build "critical=1  high=0 ..." by joining one piece per severity.
    pdf.kv("By severity", "  ".join(f"{s}={counts[s]}" for s in SEVERITIES))
    pdf.kv("CVEs referenced", str(len(audit_data.get("cves", []))))


def _render_task(pdf, task):
    # Draw one task's section: either its findings, or a "NOT COMPLETED" block.
    name = task.get("task", "unnamed task")
    validation = task.get("validation", {}) or {}
    completed = task.get("status") == "completed"   # True/False
    attempts = task.get("attempts", 1)
    pdf.h2(f"Task: {name}")

    if not completed:
        # The task failed validation on every try - show why, so it's never blank.
        pdf.set_text_color(150, 30, 30)         # red
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
        return                                  # done with this (failed) task

    findings = task.get("findings", [])
    pdf.body(f"Status: completed on attempt {attempts}. {len(findings)} finding(s).")
    pdf.ln(1)

    if not findings:                            # completed but found nothing notable
        pdf.body("No notable findings reported for this task.")
        return

    # Sort findings worst-first using SEVERITY_RANK; key= tells sorted() how to order.
    # The lambda returns each finding's rank number (default 99 if unknown).
    for finding in sorted(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99)):
        pdf.severity_chip(finding["severity"])  # coloured badge
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 6, _safe(finding["title"]),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if finding["detail"]:                   # only print if non-empty
            pdf.body(finding["detail"])
        if finding["evidence"]:
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(90, 90, 90)
            pdf.multi_cell(0, 4.5, _safe("Evidence: " + finding["evidence"]),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if finding["cves"]:
            pdf.body("CVEs: " + ", ".join(finding["cves"]), size=9)
        pdf.ln(2)                               # gap before the next finding


def _render_cves(pdf, audit_data):
    # Draw the consolidated list of every CVE referenced across all tasks.
    cves = audit_data.get("cves", [])
    pdf.h2("Referenced CVEs")
    if not cves:                                # empty list -> say so
        pdf.body("No CVEs were referenced by any task.")
        return
    for cve in cves:
        pdf.body(f"- {cve}")


def _render_appendix(pdf, audit_data):
    # Draw the appendix: the exact prompts, AI replies, validation and raw output.
    pdf.add_page()
    pdf.h1("Appendix: Prompts, Responses & Raw Output")
    for task in audit_data.get("tasks", []):
        pdf.h2(f"Task: {task.get('task', 'unnamed')}")
        pdf.body("System prompt:", size=9)
        pdf.mono(task.get("system_prompt", ""))
        pdf.body("User prompt:", size=9)
        pdf.mono(task.get("user_prompt", ""))
        pdf.body("AI response (raw):", size=9)
        # json.dumps turns the dict back into text; indent=2 pretty-prints it;
        # [:6000] truncates to 6000 chars so one huge reply can't bloat the PDF.
        pdf.mono(json.dumps(task.get("ai_response", {}), indent=2)[:6000])
        pdf.body("Validation:", size=9)
        pdf.mono(json.dumps(task.get("validation", {}), indent=2)[:3000])
        output = task.get("script_output")
        if output is not None:                  # only present for tasks that actually ran
            pdf.body("Raw script output:", size=9)
            pdf.mono(json.dumps(output, indent=2)[:6000])


def write_pdf_report(audit_data, output_path):
    # Public function: build the whole PDF and write it to output_path.
    # [REQUIREMENT: Module os] os.path.dirname gets the folder part of the path;
    # "or '.'" handles a bare filename; makedirs creates it (exist_ok = don't error if present).
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    pdf = _AuditPDF()                           # create our custom PDF object
    pdf._title_target = _safe(audit_data.get("target", ""))   # header text for every page
    pdf.alias_nb_pages()                        # makes the {nb} total-pages placeholder work

    # Build the document section by section, in order.
    _render_cover(pdf, audit_data)
    _render_profile(pdf, audit_data.get("profile", {}))
    _render_summary(pdf, audit_data)
    for task in audit_data.get("tasks", []):    # one section per task
        _render_task(pdf, task)
    _render_cves(pdf, audit_data)
    _render_appendix(pdf, audit_data)

    pdf.output(output_path)                     # finally, write the PDF file to disk
    return output_path


# --------------------------------------------------------------------------
# Logging / saving generated output. This is where File handling happens.
# --------------------------------------------------------------------------

def _slug(value):
    # Make a string safe to use in a filename: replace anything that isn't a
    # letter/digit/dot/underscore/hyphen with "_". [REQUIREMENT: Casting] str(value)
    # first so non-string values (e.g. None) still work. "x or 'target'" handles "".
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value)) or "target"


def _timestamp():
    # A compact UTC timestamp like "20260621T035420Z" for unique filenames.
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def save_run_log(audit_data, log_dir="logs"):
    # Write the whole run (profile + every prompt/response/validation/output) to
    # a JSON file, so there is a durable record of what was collected and produced.
    os.makedirs(log_dir, exist_ok=True)         # [REQUIREMENT: Module os] ensure logs/ exists
    # os.path.join builds "logs/audit_<target>_<timestamp>.json" portably.
    path = os.path.join(
        log_dir, f"audit_{_slug(audit_data.get('target'))}_{_timestamp()}.json")
    # [REQUIREMENT: File handling] open the file in "w" (write) mode. The "with"
    # block auto-closes it afterwards. json.dump writes the dict straight into it;
    # default=str converts anything not normally JSON-serialisable to a string.
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(audit_data, handle, indent=2, default=str)
    return path                                 # hand back where we saved it


def save_generated_scripts(audit_data, scripts_dir="generated_scripts"):
    # Save each AI-generated script to its own .py file for manual review.
    os.makedirs(scripts_dir, exist_ok=True)     # [REQUIREMENT: Module os] ensure the folder exists
    timestamp = _timestamp()                    # one timestamp for the whole batch
    saved = []                                  # collect the paths we write
    for task in audit_data.get("tasks", []):
        # (task.get("ai_response") or {}) guards against a missing ai_response.
        script = (task.get("ai_response") or {}).get("script")
        if not script:                          # nothing to save for this task
            continue
        # Filename includes the task name and its status so rejected scripts stand out.
        name = f"{_slug(task.get('task'))}_{task.get('status', 'unknown')}_{timestamp}.py"
        path = os.path.join(scripts_dir, name)
        # [REQUIREMENT: File handling] open for writing and write the script text.
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        saved.append(path)
    return saved                                # list of files written
