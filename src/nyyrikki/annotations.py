"""Deterministic data warnings for suspicious content inside event fields.

Event fields such as account or workstation names can be set by an attacker. Text in
them that looks like instructions (for example to an AI model) is reported as a data
warning. A warning is an indicator for a human to review, not a detection of an attack,
and the text is never treated as an instruction.
"""

from __future__ import annotations

import re

from nyyrikki.findings import Finding

_INSTRUCTION_LIKE = re.compile(
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions"
    r"|disregard\s+(?:all\s+|the\s+)?(?:previous|prior|above)"
    r"|new\s+instructions"
    r"|(?:you\s+must|you\s+should)\s+(?:reply|respond|answer|say|state|classify)"
    r"|(?:reply|respond|answer)\s+only"
    r"|system\s+prompt"
    r"|\b(?:system|assistant|user)\s*:"
    r"|</?\s*(?:event|system|assistant|user|instructions?)\b"
    r"|\[record:\d+\]"
    r"|classify\s+(?:this|it|the\s+event)\s+as"
    r"|ohita\s+.*ohjee",  # Finnish: "ignore ... instructions"
    re.IGNORECASE,
)

WARNING = (
    "contains instruction-like text; it is untrusted event data, was not followed, "
    "and the unusual value may itself warrant investigation"
)


def instruction_like_fields(finding: Finding) -> list[dict[str, object]]:
    """One warning per field name, listing every record whose value in that field is instruction-like."""
    by_field: dict[str, list[int]] = {}
    for item in finding.evidence:
        values = dict(item.fields)
        values["Computer"] = item.computer
        for field, value in values.items():
            if value and _INSTRUCTION_LIKE.search(value):
                by_field.setdefault(field, []).append(item.record_id)
    return [{"field": f, "record_ids": ids, "warning": WARNING} for f, ids in by_field.items()]


def annotate(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        finding.data_warnings = instruction_like_fields(finding)
    return findings
