# report_writer.py - parses each task's JSON output, then builds the PDF and saves the run
# log + generated scripts. Architectural role: the "presentation/output" layer. It is the only
# module that knows about PDF formatting and on-disk files, so the rest of the program stays
# format-agnostic and just hands it a finished audit_data dict.

import json                              # JSON codec. loads = text->obj; dumps = obj->text; dump = obj->file.
import os                                # [REQUIREMENT: Module os] path building + directory creation.
import re                                # regex: detect CVE ids and sanitise filenames.
from datetime import datetime, timezone  # `from X import Y` pulls specific names out of a module.

from fpdf import FPDF                     # third-party PDF engine. We SUBCLASS this class below.
from fpdf.enums import XPos, YPos         # enums telling fpdf where to move the cursor after writing.

# A TUPLE (immutable, ordered) of severities, worst -> least. Immutability signals "this list
# of valid levels never changes at runtime."
SEVERITIES = ("critical", "high", "medium", "low", "info")
# DICT COMPREHENSION: "{key: value for ... }". enumerate(SEVERITIES) yields (index, name) pairs:
# (0,"critical"),(1,"high")... so this maps each name to its rank number, used for sorting later.
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}
# A plain dict mapping each severity to an (R, G, B) colour tuple (0-255 each) for its PDF badge.
SEVERITY_RGB = {
    "critical": (138, 11, 11),
    "high": (191, 54, 12),
    "medium": (191, 130, 0),
    "low": (33, 102, 33),
    "info": (60, 80, 110),
}
# re.compile builds a reusable pattern OBJECT once. Pattern: "CVE-" then \d{4} (exactly 4 digits),
# "-", then \d{4,7} (4 to 7 digits). re.IGNORECASE lets "cve-..." match too.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# --------------------------------------------------------------------------
# JSON extraction helpers (main.py calls extract_findings / extract_cves).
# [REQUIREMENT: Functions] each is a small, independently testable unit.
# --------------------------------------------------------------------------

def _coerce_output(script_output):
    # WHY (logic): callers may hand us the {"output","errors"} dict, a bare string, or None.
    # This normalises all of them to "the stdout text," so the parsers below have one input type.
    if not script_output:                       # None or empty -> "" (both are falsy)
        return ""
    # isinstance(obj, type) returns True if obj is that type (or a subclass). The standard,
    # duck-typing-friendly way to check a type before treating a value as a dict.
    if isinstance(script_output, dict):
        return script_output.get("output", "") or ""   # the stdout field, or "" if missing/empty
    # [REQUIREMENT: Casting] str(...) converts any other type to its string form as a fallback.
    return str(script_output)


def _load_json(text):
    # WHY (logic): best-effort JSON parsing. Returns a Python object or None - never raises - so
    # callers can branch cleanly on the result.
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)                 # parse the whole string; raises JSONDecodeError if invalid
    except json.JSONDecodeError:
        pass                                    # not pure JSON -> try the fallback below
    # Fallback: the model may have wrapped JSON in prose. str.find("{") returns the index of the
    # FIRST "{" (or -1); str.rfind("}") returns the index of the LAST "}" (searching from the right).
    start, end = text.find("{"), text.rfind("}")   # TUPLE ASSIGNMENT: two names from one (a, b) line
    if 0 <= start < end:                        # CHAINED comparison: both found AND in the right order
        try:
            # SLICE text[start:end + 1] takes the substring from the first "{" to the last "}"
            # inclusive (the +1 because the slice end index is EXCLUSIVE).
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _normalize_finding(finding):
    # WHY (logic): coerce one finding into the EXACT keys/shape the PDF expects, with safe
    # defaults, so a sloppy or partial model reply can never break rendering downstream.
    # [REQUIREMENT: Casting] str(...) makes .strip()/.lower() safe even if the model sent a number/None.
    severity = str(finding.get("severity", "info")).strip().lower()
    if severity not in SEVERITY_RANK:           # clamp anything unexpected to a known level
        severity = "info"
    cves = finding.get("cves") or []            # missing/None -> empty list
    if isinstance(cves, str):                   # if the model sent a single string instead of a list,
        cves = [cves]                           # wrap it so the comprehension below can iterate it
    return {
        "title": str(finding.get("title", "Untitled finding")).strip(),
        "severity": severity,
        "detail": str(finding.get("detail", "")).strip(),
        "evidence": str(finding.get("evidence", "")).strip(),
        # SET COMPREHENSION "{... for ... if ...}": builds a SET (auto-deduplicates). For each cve we
        # upper-case it, but only KEEP it if CVE_RE.fullmatch(...) succeeds - fullmatch requires the
        # WHOLE string to match the pattern (stricter than search). sorted() turns the set into a list.
        "cves": sorted({c.upper() for c in cves if CVE_RE.fullmatch(str(c).strip())}),
    }


def extract_findings(script_output):
    # WHY (logic): parse the standardized findings list out of one task's output.
    text = _coerce_output(script_output)        # normalise to stdout text
    data = _load_json(text)                     # try to parse it
    if data is None:                            # parsing failed
        if not text.strip():                    # ...and there was no output at all
            return []                           # -> genuinely no findings
        # There WAS output but it wasn't valid JSON. Rather than silently lose it, surface it as a
        # single low-priority "info" finding so the human still sees the raw text. text[:2000] caps length.
        return [_normalize_finding({
            "title": "Unparsed audit output",
            "severity": "info",
            "detail": "Script output was not valid JSON matching the schema.",
            "evidence": text[:2000],
        })]
    # data parsed. Ternary guards that data is a dict before .get("findings"). Then a LIST
    # COMPREHENSION normalises each finding, skipping non-dict junk via the trailing `if isinstance`.
    raw_findings = data.get("findings", []) if isinstance(data, dict) else []
    return [_normalize_finding(f) for f in raw_findings if isinstance(f, dict)]


def extract_cves(script_output):
    # WHY (logic): collect every CVE id this task referenced, de-duplicated.
    cves = set()                                # a set() automatically discards duplicate ids
    for finding in extract_findings(script_output):
        cves.update(finding["cves"])            # set.update(iterable) adds ALL items from the iterable
    # Backstop: also regex-scan the raw text for CVEs the model mentioned OUTSIDE the cves field.
    # CVE_RE.findall returns every match as a list; the generator upper-cases each before update().
    cves.update(m.upper() for m in CVE_RE.findall(_coerce_output(script_output)))
    return sorted(cves)                         # return a deterministic, sorted list


# --------------------------------------------------------------------------
# PDF template
# --------------------------------------------------------------------------

def _safe(text):
    # WHY (logic): fpdf's built-in fonts only support the Latin-1 character set, so an exotic
    # character would crash output. This makes any text safe to write.
    # HOW (syntax): str(text).encode("latin-1", "replace") converts the string to BYTES in the
    # Latin-1 encoding, substituting "?" for unsupported chars ("replace" error handler); .decode(
    # "latin-1") converts those bytes back to a clean str. Net effect: a render-safe string.
    return str(text).encode("latin-1", "replace").decode("latin-1")


# [REQUIREMENT: Classes] _AuditPDF is a CLASS that INHERITS from FPDF (the "(FPDF)" means subclass).
# WHY inherit: fpdf automatically calls header()/footer() on every page; by OVERRIDING them we get a
# consistent branded header and page numbers for free. We also add helper METHODS (h1, kv, ...) so
# the render functions share one visual style. Methods take `self` (the instance) as first parameter.
class _AuditPDF(FPDF):
    def __init__(self):
        # __init__ is the CONSTRUCTOR, run when you write _AuditPDF(). super().__init__() calls the
        # PARENT class's constructor (FPDF's) first - essential, or the PDF object is half-built.
        super().__init__()
        self.set_auto_page_break(auto=True, margin=18)   # auto-start new pages, keep an 18mm bottom margin
        self.set_title("Defensive AI Audit Report")      # sets PDF metadata
        self._on_cover = False                  # instance attribute (a flag); True only while drawing the cover

    def header(self):
        # OVERRIDE: fpdf calls this automatically at the top of every page. We skip it on the cover.
        if self._on_cover:
            return                              # early return draws nothing on the cover page
        self.set_font("Helvetica", "I", 8)      # family, style ("I"=italic), size in points
        self.set_text_color(120, 120, 120)      # RGB grey
        self.cell(0, 8, "Defensive AI Audit Report", align="L")   # cell(width0=full, height, text); left-aligned
        self.cell(0, 8, self._title_target, align="R",            # right-aligned target name
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)            # then move cursor to next line at left margin
        self.set_draw_color(200, 200, 200)
        # line(x1, y1, x2, y2): draw a rule from left margin to right margin at the current y.
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)                              # ln(h) moves the cursor DOWN h mm (vertical space)

    def footer(self):
        # OVERRIDE: fpdf calls this at the bottom of every page.
        self.set_y(-15)                         # set_y with a NEGATIVE value = 15mm up from the bottom
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        # {{nb}} is an fpdf placeholder replaced with the TOTAL page count (enabled by alias_nb_pages()).
        # In an f-string, "{{" and "}}" are literal braces (escaped), so this prints "Page 1/{nb}" etc.
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    # --- small reusable drawing helpers used by the render functions below ---

    def h1(self, text):
        # A big page title. multi_cell wraps long text across lines (vs cell, which is single-line).
        self.set_font("Helvetica", "B", 16)     # "B" = bold
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 9, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def h2(self, text):
        # A section heading with an underline rule beneath it.
        self.ln(2)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(30, 50, 80)
        self.multi_cell(0, 7, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(210, 210, 210)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def kv(self, label, value):
        # One "Label:  value" row (used for the system-profile table).
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(40, 40, 40)
        self.cell(45, 6, _safe(label), new_x=XPos.RIGHT, new_y=YPos.TOP)   # fixed 45mm label, cursor stays on line
        self.set_font("Helvetica", "", 10)      # "" = regular weight
        self.set_text_color(20, 20, 20)
        # `value if value not in (None, "") else "-"` shows a dash for empty/missing values.
        self.multi_cell(0, 6, _safe(value if value not in (None, "") else "-"),
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def body(self, text, size=10):
        # A normal wrapped paragraph. `size=10` is a DEFAULT ARGUMENT callers can override.
        self.set_font("Helvetica", "", size)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 5.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def mono(self, text, size=8):
        # Monospaced block (Courier) for prompts/JSON in the appendix - alignment is preserved.
        self.set_font("Courier", "", size)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 4.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def severity_chip(self, severity):
        # Draw a small coloured badge for a finding's severity.
        # TUPLE UNPACKING: dict.get returns an (r,g,b) tuple, unpacked into three variables at once.
        r, g, b = SEVERITY_RGB.get(severity, SEVERITY_RGB["info"])
        self.set_fill_color(r, g, b)            # the badge's background colour
        self.set_text_color(255, 255, 255)      # white text on the coloured fill
        self.set_font("Helvetica", "B", 8)
        # [REQUIREMENT: Casting] str.upper() returns a NEW upper-cased string. fill=True paints the cell.
        self.cell(24, 5, _safe(severity.upper()), align="C", fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(20, 20, 20)         # reset colour for whatever is drawn next


def _severity_counts(findings):
    # WHY (logic): tally how many findings fall into each severity, for the summary.
    counts = {name: 0 for name in SEVERITIES}   # dict comprehension seeds every bucket at 0
    for finding in findings:
        # dict.get(key, 0) reads the current count (default 0); we add 1 and store it back.
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return counts


def _render_cover(pdf, audit_data):
    # WHY (logic): the title page. We set the flag so header() stays blank here.
    pdf._on_cover = True
    pdf.add_page()                              # add_page() starts a fresh page
    pdf.ln(40)                                  # push the title down 40mm
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(20, 20, 20)
    pdf.multi_cell(0, 12, "Defensive AI Audit Report", align="C",
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)
    profile = audit_data.get("profile", {})     # the profile dict, or {} if absent
    # datetime.now(timezone.utc) gets the current time AS a timezone-aware UTC datetime; .strftime
    # ("string format time") formats it using codes: %Y=4-digit year, %m=month, %d=day, %H:%M=hour:min.
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(60, 60, 60)
    # Iterate a TUPLE of three f-string subtitle lines and centre each.
    for line in (
        f"Target: {audit_data.get('target', 'unknown')}",
        f"OS: {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})",
        f"Generated: {generated}",
    ):
        pdf.multi_cell(0, 8, _safe(line), align="C",
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf._on_cover = False                        # cover done; normal headers resume


def _render_profile(pdf, profile):
    # WHY (logic): show every piece of collected info as a label/value row.
    pdf.add_page()
    pdf._title_target = _safe(profile.get("os", ""))   # set the per-page running-header text
    pdf.h1("System Profile")
    # Iterate a tuple of (display label, profile-dict key) pairs; unpack each into two names.
    for label, key in (
        ("Platform", "platform"), ("OS", "os"), ("OS release", "os_release"),
        ("Architecture", "arch"), ("Python", "python_version"),
        ("Privilege", "privilege"), ("CPU", "cpu"), ("Memory", "memory"),
    ):
        pdf.kv(label, profile.get(key, "-"))
    tools = profile.get("tools") or []          # list of tool names, or [] if missing
    pdf.kv("Tools", ", ".join(tools) if tools else "-")   # join into a single string, or "-" if empty
    network = profile.get("network") or []
    pdf.kv("Network", ", ".join(network) if network else "-")
    packages = profile.get("packages") or []
    if packages:
        # len(packages) is the count; ", ".join(packages) lists them all on this row.
        pdf.kv("Python packages", f"{len(packages)} installed: " + ", ".join(packages))
    else:
        pdf.kv("Python packages", "-")


def _render_summary(pdf, audit_data):
    # WHY (logic): an at-a-glance dashboard before the detailed task sections.
    findings = audit_data.get("findings", [])
    tasks = audit_data.get("tasks", [])
    completed = sum(1 for t in tasks if t.get("status") == "completed")   # count completed (generator + sum)
    incomplete = len(tasks) - completed
    counts = _severity_counts(findings)

    pdf.h2("Summary")
    pdf.kv("Tasks completed", f"{completed} of {len(tasks)} attempted")
    if incomplete:                              # only show this row when some tasks failed
        pdf.kv("Not completed", f"{incomplete} (failed safety validation; see task sections)")
    # [REQUIREMENT: Casting] str(len(...)) turns the integer count into the text the cell needs.
    pdf.kv("Total findings", str(len(findings)))
    # GENERATOR inside join builds "critical=N  high=N ..." from each severity bucket.
    pdf.kv("By severity", "  ".join(f"{s}={counts[s]}" for s in SEVERITIES))
    pdf.kv("CVEs referenced", str(len(audit_data.get("cves", []))))


def _render_task(pdf, task):
    # WHY (logic): one section per task - either its findings, or an explicit "NOT COMPLETED"
    # block so a failed task is never silently blank.
    name = task.get("task", "unnamed task")
    validation = task.get("validation", {}) or {}
    completed = task.get("status") == "completed"   # comparison yields a bool
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
        return                                  # done with this failed task

    findings = task.get("findings", [])
    pdf.body(f"Status: completed on attempt {attempts}. {len(findings)} finding(s).")
    pdf.ln(1)

    if not findings:                            # completed but nothing notable
        pdf.body("No notable findings reported for this task.")
        return

    # sorted(iterable, key=...) returns a NEW sorted list. The key= is a function applied to each
    # item to decide order; here a LAMBDA (an anonymous inline function) returns each finding's
    # severity rank, so findings print worst-first (lower rank number = more severe).
    for finding in sorted(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99)):
        pdf.severity_chip(finding["severity"])  # coloured badge
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 6, _safe(finding["title"]),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if finding["detail"]:                   # only print non-empty fields
            pdf.body(finding["detail"])
        if finding["evidence"]:
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(90, 90, 90)
            pdf.multi_cell(0, 4.5, _safe("Evidence: " + finding["evidence"]),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if finding["cves"]:
            pdf.body("CVEs: " + ", ".join(finding["cves"]), size=9)
        pdf.ln(2)                               # spacing before the next finding


def _render_cves(pdf, audit_data):
    # WHY (logic): one consolidated list of every CVE referenced across all tasks.
    cves = audit_data.get("cves", [])
    pdf.h2("Referenced CVEs")
    if not cves:                                # empty list is falsy
        pdf.body("No CVEs were referenced by any task.")
        return
    for cve in cves:
        pdf.body(f"- {cve}")


def _render_appendix(pdf, audit_data):
    # WHY (logic): full transparency - the exact prompts, raw AI replies, validation, and output,
    # so a reviewer can audit precisely what was sent and received.
    pdf.add_page()
    pdf.h1("Appendix: Prompts, Responses & Raw Output")
    for task in audit_data.get("tasks", []):
        pdf.h2(f"Task: {task.get('task', 'unnamed')}")
        pdf.body("System prompt:", size=9)
        pdf.mono(task.get("system_prompt", ""))
        pdf.body("User prompt:", size=9)
        pdf.mono(task.get("user_prompt", ""))
        pdf.body("AI response (raw):", size=9)
        # json.dumps(obj, indent=2) serialises a Python object back INTO pretty-printed JSON text;
        # indent=2 adds 2-space indentation. [:6000] then slices it so one huge reply can't bloat the PDF.
        pdf.mono(json.dumps(task.get("ai_response", {}), indent=2)[:6000])
        pdf.body("Validation:", size=9)
        pdf.mono(json.dumps(task.get("validation", {}), indent=2)[:3000])
        output = task.get("script_output")
        if output is not None:                  # `is not None` distinguishes "ran but empty" from "never ran"
            pdf.body("Raw script output:", size=9)
            pdf.mono(json.dumps(output, indent=2)[:6000])


def write_pdf_report(audit_data, output_path):
    # WHY (logic): the public PDF entry point. Builds the document section by section, then writes it.
    # HOW (syntax): os.path.dirname(path) returns the FOLDER part of a path; `or "."` handles a bare
    # filename (dirname returns ""); os.makedirs(path, exist_ok=True) creates the folder (and parents),
    # and exist_ok=True means "don't error if it already exists." [REQUIREMENT: Module os]
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    pdf = _AuditPDF()                           # instantiate our subclass (runs __init__)
    pdf._title_target = _safe(audit_data.get("target", ""))   # header text for every page
    pdf.alias_nb_pages()                        # makes the {nb} total-pages placeholder work

    # Compose the report in order. Each helper draws one part onto the shared pdf object.
    _render_cover(pdf, audit_data)
    _render_profile(pdf, audit_data.get("profile", {}))
    _render_summary(pdf, audit_data)
    for task in audit_data.get("tasks", []):    # one section per task
        _render_task(pdf, task)
    _render_cves(pdf, audit_data)
    _render_appendix(pdf, audit_data)

    pdf.output(output_path)                     # serialise the whole document to the file on disk
    return output_path


# --------------------------------------------------------------------------
# Logging / saving generated output. This is where File handling happens.
# --------------------------------------------------------------------------

def _slug(value):
    # WHY (logic): make any value safe to embed in a filename (no spaces/slashes/odd chars).
    # HOW (syntax): re.sub(pattern, replacement, string) returns a NEW string with every pattern
    # match replaced. [^A-Za-z0-9._-] is a NEGATED class: "any char that is NOT a letter/digit/dot/
    # underscore/hyphen" -> replaced with "_". str(value) CASTs first [REQUIREMENT: Casting] so non-
    # strings work; `... or "target"` substitutes a default if the result is empty.
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value)) or "target"


def _timestamp():
    # A compact UTC timestamp like "20260621T035420Z" - sortable and filename-safe. %S = seconds.
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def save_run_log(audit_data, log_dir="logs"):
    # WHY (logic): write a durable JSON record of the WHOLE run (profile + every prompt, reply,
    # validation, and output). This is the audit trail.
    os.makedirs(log_dir, exist_ok=True)         # [REQUIREMENT: Module os] ensure the logs/ folder exists
    # os.path.join joins path parts with the OS-correct separator ("/" or "\"), avoiding manual string glue.
    path = os.path.join(
        log_dir, f"audit_{_slug(audit_data.get('target'))}_{_timestamp()}.json")
    # [REQUIREMENT: File handling] open(path, "w") opens the file for WRITING (creating/truncating it).
    # `with ... as handle` is a context manager that GUARANTEES the file is closed afterwards, even on
    # error. json.dump(obj, file) writes JSON straight into the open file; default=str tells it to
    # convert any object it can't natively serialise into a string instead of raising.
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(audit_data, handle, indent=2, default=str)
    return path                                 # tell the caller where we saved it


def save_generated_scripts(audit_data, scripts_dir="generated_scripts"):
    # WHY (logic): write each AI-generated script to its own .py file so a human can review them.
    os.makedirs(scripts_dir, exist_ok=True)     # [REQUIREMENT: Module os] ensure the folder exists
    timestamp = _timestamp()                    # one shared timestamp for the whole batch
    saved = []                                  # collect the paths we wrote, to return
    for task in audit_data.get("tasks", []):
        # (task.get("ai_response") or {}) guards against a missing/None ai_response before .get("script").
        script = (task.get("ai_response") or {}).get("script")
        if not script:                          # nothing to save for this task
            continue                            # skip to the next task
        # Build a descriptive filename: task name + status + timestamp, so rejected scripts stand out.
        name = f"{_slug(task.get('task'))}_{task.get('status', 'unknown')}_{timestamp}.py"
        path = os.path.join(scripts_dir, name)
        # [REQUIREMENT: File handling] open for writing; handle.write(str) writes the text; the `with`
        # block flushes and closes the file automatically when it ends.
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        saved.append(path)
    return saved                                # list of files written
