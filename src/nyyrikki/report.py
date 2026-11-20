"""Build and render scan reports.

JSON output is a borealis-agent-report/1 report (see standard.py). The text summary is
rendered from that same report and shows only what a person needs to review a finding,
not raw event content.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from nyyrikki import standard
from nyyrikki.findings import Finding

SEVERITIES = ("high", "medium", "low")


def build_report(
    findings: list[Finding],
    events_parsed: int,
    started_at: datetime,
    interpretations: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """`interpretations` (optional, experimental) maps a finding's index to its local-model
    result. They're keyed by finding_id and passed into standard.build(), so they count
    towards the size limit and are removed with any finding that gets dropped."""
    by_id = None
    if interpretations:
        ids = [standard.finding_dict(f, "1970-01-01T00:00:00Z")["finding_id"] for f in findings]
        by_id = {ids[i]: value for i, value in interpretations.items()}
    return standard.build(findings, events_parsed, started_at, interpretations=by_id)


def to_json(report: dict[str, Any]) -> str:
    return standard.serialise(report)


def _ranges(ids: list[int]) -> str:
    """Compress record IDs: [1, 2, 3, 7] -> '1-3, 7'."""
    ids = sorted(set(ids))
    if not ids:
        return "none"
    parts: list[str] = []
    start = prev = ids[0]
    for value in ids[1:]:
        if value == prev + 1:
            prev = value
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = value
    parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ", ".join(parts)


_ESCAPES = {chr(10): chr(92) + "n", chr(13): chr(92) + "r", chr(9): chr(92) + "t"}


def _safe(value: object) -> str:
    """Render a value on one line. Event content is untrusted: newlines, tabs and any other
    control characters are shown as visible escapes, so a crafted account name cannot add
    lines or imitate report headings. The JSON report keeps the original value."""
    out = []
    for ch in str(value):
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F:
            out.append(chr(92) + f"x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def _record_id(ref: str) -> int | None:
    tail = ref.rsplit(":", 1)[-1]
    return int(tail) if tail.isdigit() else None


def _when(evidence: list[dict[str, Any]]) -> str:
    times = sorted(item["timestamp"] for item in evidence if item.get("timestamp"))
    if not times:
        return "unknown"
    first, last = (t.replace("T", " ").replace("Z", " UTC") for t in (times[0], times[-1]))
    return first if first == last else f"{first} to {last}"


def _accounts(evidence: list[dict[str, Any]]) -> str:
    names: list[str] = []
    for item in evidence:
        fields = item.get("details", {}).get("fields", {})
        for key in ("MemberName", "MemberSid", "TargetUserName", "SubjectUserName"):
            name = fields.get(key, "")
            if name and name != "-" and name not in names:
                names.append(name)
                break
    return ", ".join(_safe(n) for n in names)


def to_text(report: dict[str, Any], source_label: str) -> str:
    """`source_label` is a generic identifier (the CLI passes `security-event-export`), never a path."""
    findings = sorted(report["findings"], key=lambda f: SEVERITIES.index(f["severity"]))
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in SEVERITIES}
    events = sum(item.get("count", 0) for item in report["source"]["scope"])
    interpretations = report.get("extensions", {}).get("experimental_interpretations", {})
    lines = [
        "Nyyrikki Security Report",
        "========================",
        "",
        f"Source:          {_safe(source_label)}",
        f"Events analysed: {events}",
        f"Findings:        {report['findings_total']}",
        f"  High:   {counts['high']}",
        f"  Medium: {counts['medium']}",
        f"  Low:    {counts['low']}",
    ]
    if report["status"] != "ok":
        lines += ["", f"Report status: {report['status']} ({report['errors_total']} problem(s)):"]
        lines += [f"  {_safe(e['code'])}: {_safe(e['message'])}" for e in report["errors"]]

    if not findings:
        lines += [
            "",
            "No findings. This does not mean the system is safe: Nyyrikki only applies",
            "its rules (docs/detections.md) to the events contained in this file.",
        ]
        return "\n".join(lines) + "\n"

    lines.append("Severity is a rule label, not a probability.")
    for number, finding in enumerate(findings, start=1):
        evidence = finding["evidence"]
        heading = f"Finding {number}: {finding['severity'].capitalize()} ({finding['rule_id']})"
        lines += ["", heading, "-" * len(heading)]
        lines += ["What happened:", f"  {_safe(finding['observation'])}"]
        lines += ["When:", f"  {_when(evidence)}"]
        accounts = _accounts(evidence)
        if accounts:
            lines += ["Account:", f"  {accounts}"]
        lines += ["Why it matters:", f"  {_safe(finding['assessment'])}"]
        lines += ["Recommended action:", f"  {_safe(finding['recommendation'])}"]
        ids = [i for i in (_record_id(e["ref"]) for e in evidence) if i is not None]
        listed = "" if finding["evidence_total"] == len(evidence) else f" (first {len(evidence)} listed)"
        lines += [
            "Evidence references:",
            f"  {finding['evidence_total']} event(s), record IDs: {_ranges(ids)}{listed}",
        ]
        for warning in finding.get("data_warnings", []):
            refs = [i for i in (_record_id(r) for r in warning["refs"]) if i is not None]
            lines += ["Data warning:", f"  Field {_safe(warning['field'])} in record(s) {_ranges(refs)} {_safe(warning['warning'])}."]
        interpretation = interpretations.get(finding["finding_id"], {})
        if interpretation.get("interpretation"):
            lines += ["AI interpretation (local model; not evidence, verify against the records):",
                      f"  {_safe(interpretation['interpretation'])}"]
        if interpretation.get("rejected"):
            lines += ["AI interpretation rejected:", f"  {_safe(interpretation['rejected'])}"]
        lines += ["Limitations:", f"  {_safe(finding['limitations'])}"]

    lines += ["", "To verify, look up the record IDs in Event Viewer (Windows Logs > Security)."]
    return "\n".join(lines) + "\n"
