"""Build and render scan reports: human-readable text for people, JSON for programs.

The JSON schema is versioned (SCHEMA_VERSION) so a future Borealis Node can rely on it.
The text summary deliberately shows only what a person needs to review a finding,
not raw event content.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from nyyrikki import __version__
from nyyrikki.findings import AGENT, Finding

SCHEMA_VERSION = 1
SEVERITIES = ("high", "medium", "low")


def build_report(source: str, events_parsed: int, findings: list[Finding]) -> dict[str, Any]:
    items = [finding.to_dict() for finding in findings]
    by_severity = {sev: sum(1 for f in items if f["severity"] == sev) for sev in SEVERITIES}
    return {
        "schema_version": SCHEMA_VERSION,
        "agent": AGENT,
        "version": __version__,
        "run": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": source,
        },
        "counts": {"events": events_parsed, "findings": len(items), **by_severity},
        "findings": items,
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2) + "\n"


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


def _when(evidence: list[dict[str, Any]]) -> str:
    times = sorted(item.get("time_created", "") for item in evidence if item.get("time_created"))
    if not times:
        return "unknown"
    first, last = (t.replace("T", " ").replace("+00:00", " UTC") for t in (times[0], times[-1]))
    return first if first == last else f"{first} to {last}"


def _accounts(evidence: list[dict[str, Any]]) -> str:
    names: list[str] = []
    for item in evidence:
        fields = item.get("fields", {})
        for key in ("MemberName", "MemberSid", "TargetUserName", "SubjectUserName"):
            name = fields.get(key, "")
            if name and name != "-" and name not in names:
                names.append(name)
                break
    return ", ".join(names)


def to_text(report: dict[str, Any]) -> str:
    counts = report["counts"]
    findings = sorted(
        report["findings"],
        key=lambda f: SEVERITIES.index(f["severity"]) if f.get("severity") in SEVERITIES else 9,
    )
    lines = [
        "Nyyrikki Security Report",
        "========================",
        "",
        f"Source:          {report['run']['source']}",
        f"Events analysed: {counts['events']}",
        f"Findings:        {counts['findings']}",
        f"  High:   {counts['high']}",
        f"  Medium: {counts['medium']}",
        f"  Low:    {counts['low']}",
    ]

    if not findings:
        lines += [
            "",
            "No findings. This does not mean the system is safe: Nyyrikki only applies",
            "its rules (docs/detections.md) to the events contained in this file.",
        ]
        return "\n".join(lines) + "\n"

    lines.append("Severity is a rule label, not a probability.")
    for number, finding in enumerate(findings, start=1):
        evidence = finding.get("evidence", [])
        heading = f"Finding {number}: {str(finding.get('severity', 'unknown')).capitalize()} ({finding.get('rule_id', '')})"
        lines += ["", heading, "-" * len(heading)]
        lines += ["What happened:", f"  {finding.get('observation', '')}"]
        lines += ["When:", f"  {_when(evidence)}"]
        accounts = _accounts(evidence)
        if accounts:
            lines += ["Account:", f"  {accounts}"]
        lines += ["Why it matters:", f"  {finding.get('assessment', '')}"]
        lines += ["Recommended action:", f"  {finding.get('recommendation', '')}"]
        lines += [
            "Evidence references:",
            f"  {len(evidence)} event(s), record IDs: {_ranges([i['record_id'] for i in evidence if 'record_id' in i])}",
        ]
        if finding.get("interpretation"):
            lines += ["AI interpretation (local model; not evidence, verify against the records):",
                      f"  {finding['interpretation']}"]
        if finding.get("interpretation_rejected"):
            lines += ["AI interpretation rejected:", f"  {finding['interpretation_rejected']}"]
        lines += ["Limitations:", f"  {finding.get('limitations', '')}"]

    lines += ["", "To verify, look up the record IDs in Event Viewer (Windows Logs > Security)."]
    return "\n".join(lines) + "\n"
