"""Produces the final paginated PDF audit report from a standardized JSON
contract, and exposes the helpers main.py uses to pull structured findings
and CVEs out of each task's script output.

Every audit script is instructed (by prompt_builder) to print one JSON object
matching a fixed findings schema, so this module can render one consistent PDF
template for everything found at runtime instead of parsing free-form text.

Expected per-task script output (from target_connector.execute_script):
    {"output": "<stdout, a JSON findings object>", "errors": "<stderr>"}

Findings JSON schema:
    {"task": "...", "findings": [
        {"title", "severity", "detail", "evidence", "cves": [...]}, ...]}
"""

import json
import os
import re
from datetime import datetime, timezone

from fpdf import FPDF
from fpdf.enums import XPos, YPos

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}
SEVERITY_RGB = {
    "critical": (138, 11, 11),
    "high": (191, 54, 12),
    "medium": (191, 130, 0),
    "low": (33, 102, 33),
    "info": (60, 80, 110),
}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# --------------------------------------------------------------------------
# JSON extraction helpers (consumed by main.py per task)
# --------------------------------------------------------------------------

def _coerce_output(script_output):
    """target_connector returns {"output", "errors"}; accept that, a bare
    string, or None and return the stdout text."""
    if not script_output:
        return ""
    if isinstance(script_output, dict):
        return script_output.get("output", "") or ""
    return str(script_output)


def _load_json(text):
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Models sometimes wrap the object in stray prose; grab the outermost {...}.
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _normalize_finding(finding):
    severity = str(finding.get("severity", "info")).strip().lower()
    if severity not in SEVERITY_RANK:
        severity = "info"
    cves = finding.get("cves") or []
    if isinstance(cves, str):
        cves = [cves]
    return {
        "title": str(finding.get("title", "Untitled finding")).strip(),
        "severity": severity,
        "detail": str(finding.get("detail", "")).strip(),
        "evidence": str(finding.get("evidence", "")).strip(),
        "cves": sorted({c.upper() for c in cves if CVE_RE.fullmatch(str(c).strip())}),
    }


def extract_findings(script_output):
    """Parse the standardized JSON findings list from one task's output."""
    text = _coerce_output(script_output)
    data = _load_json(text)
    if data is None:
        if not text.strip():
            return []
        # Don't silently drop output we couldn't parse - surface it as info.
        return [_normalize_finding({
            "title": "Unparsed audit output",
            "severity": "info",
            "detail": "Script output was not valid JSON matching the schema.",
            "evidence": text[:2000],
        })]
    raw_findings = data.get("findings", []) if isinstance(data, dict) else []
    return [_normalize_finding(f) for f in raw_findings if isinstance(f, dict)]


def extract_cves(script_output):
    """Collect CVE IDs from the findings, with a regex backstop over the raw
    output in case the model mentions one outside the cves field."""
    cves = set()
    for finding in extract_findings(script_output):
        cves.update(finding["cves"])
    cves.update(m.upper() for m in CVE_RE.findall(_coerce_output(script_output)))
    return sorted(cves)


# --------------------------------------------------------------------------
# PDF template
# --------------------------------------------------------------------------

def _safe(text):
    """Core fonts are latin-1 only; replace anything outside it."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class _AuditPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=18)
        self.set_title("Defensive AI Audit Report")
        self._on_cover = False

    def header(self):
        if self._on_cover:
            return
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, "Defensive AI Audit Report", align="L")
        self.cell(0, 8, self._title_target, align="R",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(200, 200, 200)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    # --- reusable building blocks for a consistent template ---

    def h1(self, text):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 9, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def h2(self, text):
        self.ln(2)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(30, 50, 80)
        self.multi_cell(0, 7, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(210, 210, 210)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def kv(self, label, value):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(40, 40, 40)
        self.cell(45, 6, _safe(label), new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 6, _safe(value if value not in (None, "") else "-"),
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def body(self, text, size=10):
        self.set_font("Helvetica", "", size)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 5.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def mono(self, text, size=8):
        self.set_font("Courier", "", size)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 4.5, _safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def severity_chip(self, severity):
        r, g, b = SEVERITY_RGB.get(severity, SEVERITY_RGB["info"])
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        self.cell(24, 5, _safe(severity.upper()), align="C", fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(20, 20, 20)


def _severity_counts(findings):
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return counts


def _render_cover(pdf, audit_data):
    pdf._on_cover = True
    pdf.add_page()
    pdf.ln(40)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(20, 20, 20)
    pdf.multi_cell(0, 12, "Defensive AI Audit Report", align="C",
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)
    profile = audit_data.get("profile", {})
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(60, 60, 60)
    for line in (
        f"Target: {audit_data.get('target', 'unknown')}",
        f"OS: {profile.get('os', 'unknown')} ({profile.get('platform', 'unknown')})",
        f"Generated: {generated}",
    ):
        pdf.multi_cell(0, 8, _safe(line), align="C",
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf._on_cover = False


def _render_profile(pdf, profile):
    pdf.add_page()
    pdf._title_target = _safe(profile.get("os", ""))
    pdf.h1("System Profile")
    for label, key in (
        ("Platform", "platform"), ("OS", "os"), ("OS release", "os_release"),
        ("Architecture", "arch"), ("Python", "python_version"),
        ("Privilege", "privilege"), ("CPU", "cpu"), ("Memory", "memory"),
    ):
        pdf.kv(label, profile.get(key, "-"))
    tools = profile.get("tools") or []
    pdf.kv("Tools", ", ".join(tools) if tools else "-")


def _render_summary(pdf, audit_data):
    findings = audit_data.get("findings", [])
    tasks = audit_data.get("tasks", [])
    completed = sum(1 for t in tasks if t.get("status") == "completed")
    incomplete = len(tasks) - completed
    counts = _severity_counts(findings)

    pdf.h2("Summary")
    pdf.kv("Tasks completed", f"{completed} of {len(tasks)} attempted")
    if incomplete:
        pdf.kv("Not completed", f"{incomplete} (failed safety validation; see task sections)")
    pdf.kv("Total findings", str(len(findings)))
    pdf.kv("By severity", "  ".join(f"{s}={counts[s]}" for s in SEVERITIES))
    pdf.kv("CVEs referenced", str(len(audit_data.get("cves", []))))


def _render_task(pdf, task):
    name = task.get("task", "unnamed task")
    validation = task.get("validation", {}) or {}
    completed = task.get("status") == "completed"
    attempts = task.get("attempts", 1)
    pdf.h2(f"Task: {name}")

    if not completed:
        # Explicit "could not complete" block so the section is never blank.
        pdf.set_text_color(150, 30, 30)
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
        return

    findings = task.get("findings", [])
    pdf.body(f"Status: completed on attempt {attempts}. {len(findings)} finding(s).")
    pdf.ln(1)

    if not findings:
        pdf.body("No notable findings reported for this task.")
        return

    for finding in sorted(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99)):
        pdf.severity_chip(finding["severity"])
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 6, _safe(finding["title"]),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if finding["detail"]:
            pdf.body(finding["detail"])
        if finding["evidence"]:
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(90, 90, 90)
            pdf.multi_cell(0, 4.5, _safe("Evidence: " + finding["evidence"]),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if finding["cves"]:
            pdf.body("CVEs: " + ", ".join(finding["cves"]), size=9)
        pdf.ln(2)


def _render_cves(pdf, audit_data):
    cves = audit_data.get("cves", [])
    pdf.h2("Referenced CVEs")
    if not cves:
        pdf.body("No CVEs were referenced by any task.")
        return
    for cve in cves:
        pdf.body(f"- {cve}")


def _render_appendix(pdf, audit_data):
    pdf.add_page()
    pdf.h1("Appendix: Prompts, Responses & Raw Output")
    for task in audit_data.get("tasks", []):
        pdf.h2(f"Task: {task.get('task', 'unnamed')}")
        pdf.body("System prompt:", size=9)
        pdf.mono(task.get("system_prompt", ""))
        pdf.body("User prompt:", size=9)
        pdf.mono(task.get("user_prompt", ""))
        pdf.body("AI response (raw):", size=9)
        pdf.mono(json.dumps(task.get("ai_response", {}), indent=2)[:6000])
        pdf.body("Validation:", size=9)
        pdf.mono(json.dumps(task.get("validation", {}), indent=2)[:3000])
        output = task.get("script_output")
        if output is not None:
            pdf.body("Raw script output:", size=9)
            pdf.mono(json.dumps(output, indent=2)[:6000])


def write_pdf_report(audit_data, output_path):
    """Render the full standardized paginated PDF report to output_path."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    pdf = _AuditPDF()
    pdf._title_target = _safe(audit_data.get("target", ""))
    pdf.alias_nb_pages()

    _render_cover(pdf, audit_data)
    _render_profile(pdf, audit_data.get("profile", {}))
    _render_summary(pdf, audit_data)
    for task in audit_data.get("tasks", []):
        _render_task(pdf, task)
    _render_cves(pdf, audit_data)
    _render_appendix(pdf, audit_data)

    pdf.output(output_path)
    return output_path
