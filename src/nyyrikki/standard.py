"""Nyyrikki's implementation of the Borealis agent report standard (borealis-agent-report/1).

The standard is a contract, not shared code: this module implements it independently and
is tested against the published test vectors (vendored in tests/standards/).
See https://github.com/borealis-research-lab/.github/tree/main/standards
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any

from nyyrikki import __version__
from nyyrikki.findings import Finding

STANDARD = "borealis-agent-report/1"
AGENT_NAME = "nyyrikki"
RESPONSIBILITY = (
    "Identifies potentially suspicious activity in exported Windows Security events and "
    "reports it with traceable evidence."
)
PERSONAL_DATA = ["account-names", "ip-addresses", "host-names"]
REF_NAMESPACE = "windows-security"

MAX_EVIDENCE = 500
MAX_FINDINGS = 1000
MAX_REPORT_BYTES = 10 * 1024 * 1024
SIZE_EVIDENCE = 100
MAX_WARNINGS = 50
MAX_WARNING_REFS = 100
MAX_TEXT = 2000
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}

_FORBIDDEN_TEXT = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


# --- Identity -------------------------------------------------------------------------------


def record_ref(record_id: int) -> str:
    return f"{REF_NAMESPACE}:record:{record_id}"


def canonical_refs(refs: list[str]) -> list[str]:
    return sorted({unicodedata.normalize("NFC", r) for r in refs})


def evidence_refs_digest(refs: list[str]) -> str:
    return hashlib.sha256("\n".join(canonical_refs(refs)).encode("utf-8")).hexdigest()


def finding_id(rule_id: str, refs_digest: str, agent: str = AGENT_NAME) -> str:
    suffix = hashlib.sha256((rule_id + "\n" + refs_digest).encode("utf-8")).hexdigest()[:16]
    return agent + ":" + rule_id + ":" + suffix


def timestamp(value: datetime) -> str:
    """UTC timestamp with an explicit Z; fraction only when non-zero (at most 6 digits)."""
    utc = value.astimezone(timezone.utc)
    text = utc.strftime("%Y-%m-%dT%H:%M:%S")
    if utc.microsecond:
        text += f".{utc.microsecond:06d}"
    return text + "Z"


def plain_text(value: str, limit: int = MAX_TEXT) -> str:
    """Event content can be attacker-controlled: drop control characters, enforce length."""
    cleaned = _FORBIDDEN_TEXT.sub(" ", value)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


# --- Findings -----------------------------------------------------------------------------------


def _evidence_item(item) -> dict[str, Any]:
    return {
        "ref": record_ref(item.record_id),
        "timestamp": timestamp(datetime.fromisoformat(item.time_created)),
        "details": {
            "record_id": item.record_id,
            "event_id": item.event_id,
            "computer": item.computer,
            "fields": dict(item.fields),
        },
    }


def _data_warnings(finding: Finding) -> dict[str, Any]:
    warnings = sorted(finding.data_warnings, key=lambda w: w["field"])
    if not warnings:
        return {}
    listed = []
    for warning in warnings[:MAX_WARNINGS]:
        refs = canonical_refs([record_ref(r) for r in warning["record_ids"]])
        listed.append({
            "field": warning["field"],
            "refs": refs[:MAX_WARNING_REFS],
            "refs_total": len(refs),
            "warning": warning["warning"],
        })
    return {"data_warnings": listed, "data_warnings_total": len(warnings)}


def finding_dict(finding: Finding, created_at: str) -> dict[str, Any]:
    items = [_evidence_item(e) for e in finding.evidence]
    unique: dict[str, dict[str, Any]] = {}
    for item in items:  # chronological order is kept unless truncation is needed
        unique.setdefault(item["ref"], item)
    refs = list(unique)
    canon = canonical_refs(refs)
    digest = evidence_refs_digest(refs)
    evidence = list(unique.values())
    if len(evidence) > MAX_EVIDENCE:  # disclosed truncation: first 500 canonical refs
        evidence = [unique[r] for r in canon[:MAX_EVIDENCE]]
    return {
        "finding_id": finding_id(finding.rule_id, digest),
        "created_at": created_at,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "observation": plain_text(finding.observation),
        "assessment": plain_text(finding.assessment),
        "recommendation": plain_text(finding.recommendation),
        "limitations": plain_text(finding.limitations),
        "evidence": evidence,
        "evidence_total": len(canon),
        "evidence_refs_digest": digest,
        **_data_warnings(finding),
    }


def _merge_duplicates(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Findings are unique by (rule_id, evidence set); keep the first of any duplicates."""
    seen: set[str] = set()
    unique = []
    for f in findings:
        if f["finding_id"] not in seen:
            seen.add(f["finding_id"])
            unique.append(f)
    return unique


def _rank(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f["severity"]], f["finding_id"]))


# --- Report -------------------------------------------------------------------------------------


def serialise(report: dict[str, Any]) -> str:
    """The exact form written to stdout and files; the size limit is measured on this."""
    return json.dumps(report, indent=2) + "\n"


def _size(report: dict[str, Any]) -> int:
    return len(serialise(report).encode("utf-8"))


def _error_entry(code: str, message: str) -> dict[str, Any]:
    return {"code": code, "message": message}


def _apply_errors(report: dict[str, Any], errors: list[dict[str, Any]]) -> None:
    """Only report-level truncation errors exist in Nyyrikki; they're listed in the
    standard's reserved order and counted exactly."""
    order = ["findings-truncated", "evidence-truncated-for-size", "details-omitted-for-size", "report-too-large"]
    errors = sorted(errors, key=lambda e: order.index(e["code"]))
    report["errors"] = errors
    report["errors_total"] = len(errors)
    report["error_counts"] = {e["code"]: 1 for e in errors}
    report["status"] = "ok" if not errors else ("error" if any(e["code"] == "report-too-large" for e in errors) else "partial")


def build(
    findings: list[Finding],
    events_parsed: int,
    started_at: datetime,
    finished_at: datetime | None = None,
    extensions: dict[str, Any] | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Build a borealis-agent-report/1 report, applying the standard's limits."""
    created = timestamp(started_at)
    items = _merge_duplicates([finding_dict(f, created) for f in findings])
    findings_total = len(items)
    errors: list[dict[str, Any]] = []

    if len(items) > MAX_FINDINGS:
        items = _rank(items)[:MAX_FINDINGS]
        errors.append(_error_entry("findings-truncated", f"{findings_total - MAX_FINDINGS} findings dropped (count limit)"))

    report: dict[str, Any] = {
        "standard": STANDARD,
        "agent": {"name": AGENT_NAME, "version": __version__},
        "run": {
            "id": run_id or str(uuid.uuid4()),
            "started_at": created,
            "finished_at": timestamp(finished_at or datetime.now(timezone.utc)),
        },
        "source": {
            "type": "windows-security-events",
            "description": "Windows Security events exported to XML (wevtutil or Event Viewer).",
            "scope": [{"kind": "event-export", "id": "security-event-export", "count": events_parsed}],
        },
        "status": "ok",
        "errors": [],
        "errors_total": 0,
        "error_counts": {},
        "findings": items,
        "findings_total": findings_total,
    }
    if extensions:
        report["extensions"] = extensions
    _apply_errors(report, errors)
    if _size(report) > MAX_REPORT_BYTES:
        _fit_size(report, errors)
    return report


def _fit_size(report: dict[str, Any], errors: list[dict[str, Any]]) -> None:
    """The standard's three size-reduction steps, in order, re-measuring after each."""
    report["findings"] = _rank(report["findings"])

    # Step 1: evidence lists to their first 100 canonical refs (skipped if nothing to cut).
    cut = False
    for f in report["findings"]:
        if len(f["evidence"]) > SIZE_EVIDENCE:
            by_ref = {e["ref"]: e for e in f["evidence"]}
            f["evidence"] = [by_ref[r] for r in sorted(by_ref)[:SIZE_EVIDENCE]]
            cut = True
    if cut:
        errors.append(_error_entry("evidence-truncated-for-size", "evidence lists cut to 100 items to meet the size limit"))
        _apply_errors(report, errors)
        if _size(report) <= MAX_REPORT_BYTES:
            return

    # Step 2: drop evidence details.
    for f in report["findings"]:
        for e in f["evidence"]:
            e.pop("details", None)
        f["evidence_details_omitted"] = True
    errors.append(_error_entry("details-omitted-for-size", "evidence details removed to meet the size limit"))
    _apply_errors(report, errors)
    if _size(report) <= MAX_REPORT_BYTES:
        return

    # Step 3: drop findings from the end of the ranking until the report fits.
    dropped_for_count = report["findings_total"] - len(report["findings"])
    sizes = [len(json.dumps(f, indent=2).encode("utf-8")) + 6 for f in report["findings"]]
    keep = len(sizes)
    excess = _size(report) - MAX_REPORT_BYTES + 200  # 200 bytes headroom for the error message
    while keep and excess > 0:
        keep -= 1
        excess -= sizes[keep]
    while True:
        report["findings"] = report["findings"][:keep]
        dropped = dropped_for_count + len(sizes) - keep
        errors = [e for e in errors if e["code"] != "findings-truncated"]
        errors.append(_error_entry("findings-truncated", f"{dropped} findings dropped (count and size limits)"))
        _apply_errors(report, errors)
        if _size(report) <= MAX_REPORT_BYTES or keep == 0:
            break
        keep -= 1
    # The evidence-cut error describes the listed findings; drop it if every finding whose
    # evidence was cut has itself been dropped (findings-truncated already counts those).
    if not any(len(f["evidence"]) < min(MAX_EVIDENCE, f["evidence_total"]) for f in report["findings"]):
        errors = [e for e in errors if e["code"] != "evidence-truncated-for-size"]
        _apply_errors(report, errors)
    if _size(report) > MAX_REPORT_BYTES:
        report["findings"] = []
        errors.append(_error_entry("report-too-large", "report could not be fitted within 10 MiB"))
        _apply_errors(report, errors)


def describe() -> dict[str, Any]:
    return {
        "standard": STANDARD,
        "name": AGENT_NAME,
        "version": __version__,
        "responsibility": RESPONSIBILITY,
        "personal_data": PERSONAL_DATA,
    }
