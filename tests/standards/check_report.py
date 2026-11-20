"""Reference checker for the Borealis reporting standards (v1).

This module is a *reference* used to test the standards in this directory: it shows one
correct reading of the normative documents and verifies the published test vectors and
examples. It is deliberately NOT a shared runtime dependency: each agent and the Node
implement the standard independently and test themselves against the vectors.

Standard library only. Usage:

    python check_report.py agent  REPORT.json     # validate an agent report
    python check_report.py node   REPORT.json     # validate a node report
    python check_report.py vectors                # verify test-vectors-v1.json
    python check_report.py max-envelope OUT.json  # write the maximum-envelope node report
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any

AGENT_STANDARD = "borealis-agent-report/1"
NODE_STANDARD = "borealis-node-report/1"

MAX_AGENT_REPORT_BYTES = 10 * 1024 * 1024
MAX_NODE_REPORT_BYTES = 64 * 1024 * 1024
NODE_ENVELOPE_RESERVE = 8 * 1024 * 1024
NODE_EMBED_BUDGET = MAX_NODE_REPORT_BYTES - NODE_ENVELOPE_RESERVE  # 56 MiB
MAX_INT = 2**53 - 1

RESERVED_TRUNCATION_CODES = (
    "findings-truncated",
    "evidence-truncated-for-size",
    "details-omitted-for-size",
    "report-too-large",
)
OTHER_CODES = "other-codes"
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
LAUNCH_ERRORS = (
    "not-found", "not-a-file", "spawn-failed", "isolation-failed", "describe-failed", "describe-mismatch",
)

RE_AGENT_NAME = re.compile(r"^[a-z][a-z0-9-]{1,39}$")
RE_CONFIG_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
RE_CODE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
RE_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
RE_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
RE_NAMESPACE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
RE_UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
RE_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,6})?Z$")
RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")
RE_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]*$")
RE_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
RE_TEXT_FORBIDDEN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # plain text may contain \t and \n
RE_SURROGATE = re.compile(r"[\ud800-\udfff]")
RE_ABSOLUTE_PATH_HINT = re.compile(r"(?:\b[A-Za-z]:[\\/])|(?:\\\\[^\\\s]+\\)|(?:(?:^|\s)/(?:home|Users|root)/)")


# ---------------------------------------------------------------------------------------
# Canonical JSON (canonical-json-v1.md)
# ---------------------------------------------------------------------------------------


class CanonicalJsonError(ValueError):
    pass


def _cj_normalise(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise CanonicalJsonError(f"{path}: integer outside +-(2^53-1)")
        return value
    if isinstance(value, float):
        raise CanonicalJsonError(f"{path}: floats are not permitted")
    if isinstance(value, str):
        if RE_SURROGATE.search(value):
            raise CanonicalJsonError(f"{path}: unpaired surrogate (strings must be Unicode scalar values)")
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_cj_normalise(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        out = {}
        for key, v in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise CanonicalJsonError(f"{path}: object keys must be ASCII strings")
            out[key] = _cj_normalise(v, f"{path}.{key}")
        return out
    raise CanonicalJsonError(f"{path}: unsupported type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Serialise `value` as Borealis Canonical JSON v1 (UTF-8 bytes)."""
    normalised = _cj_normalise(value)
    return json.dumps(
        normalised, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------------------
# Strict JSON parsing
# ---------------------------------------------------------------------------------------


class StrictJsonError(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise StrictJsonError(f"non-standard JSON value {name}")


def _reject_float(text: str) -> Any:
    raise StrictJsonError(f"floats are not permitted ({text})")


MAX_INT_DIGITS = len(str(MAX_INT))  # 16; JSON integers have no leading zeros


def _checked_int(text: str) -> int:
    # Check the digit count before converting: unrestricted int() on thousands of digits
    # can raise ValueError (Python's conversion limit) or be slow.
    digits = text[1:] if text.startswith("-") else text
    if len(digits) > MAX_INT_DIGITS:
        raise StrictJsonError(f"integer outside +-(2^53-1) ({len(digits)} digits)")
    try:
        value = int(text)
    except ValueError:
        raise StrictJsonError("invalid integer") from None
    if abs(value) > MAX_INT:
        raise StrictJsonError(f"integer outside +-(2^53-1): {text}")
    return value


def strict_loads(data: bytes) -> Any:
    """Parse JSON per the strict-parsing rules: UTF-8 (no BOM), one value, no duplicate
    keys, no NaN/Infinity, no floats, integers within +-(2^53-1)."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise StrictJsonError("byte order mark is not permitted")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJsonError(f"not valid UTF-8 at byte {exc.start}") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
            parse_int=_checked_int,
        )
    except json.JSONDecodeError as exc:
        raise StrictJsonError(f"invalid JSON: {exc.msg} at position {exc.pos}") from None
    except RecursionError:
        raise StrictJsonError("nesting too deep") from None
    _reject_surrogates(value)
    return value


def _reject_surrogates(value: Any) -> None:
    """Escapes such as \\ud800 decode to unpaired surrogates; a valid escaped pair
    decodes to one scalar value. Strings must be sequences of Unicode scalar values."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if RE_SURROGATE.search(item):
                raise StrictJsonError("unpaired surrogate in string (strings must be Unicode scalar values)")
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())


# ---------------------------------------------------------------------------------------
# Evidence references and finding identity (agent-report-v1.md)
# ---------------------------------------------------------------------------------------


def canonical_refs(refs: list[str]) -> list[str]:
    return sorted({unicodedata.normalize("NFC", r) for r in refs})


def evidence_refs_digest(refs: list[str]) -> str:
    return sha256_hex("\n".join(canonical_refs(refs)).encode("utf-8"))


def finding_id(agent_name: str, rule_id: str, refs_digest: str) -> str:
    suffix = sha256_hex((rule_id + "\n" + refs_digest).encode("utf-8"))[:16]
    return agent_name + ":" + rule_id + ":" + suffix


def valid_ref(ref: Any) -> str | None:
    if not isinstance(ref, str):
        return "ref must be a string"
    namespace, sep, value = ref.partition(":")
    if not sep or not RE_NAMESPACE.fullmatch(namespace):
        return "ref must be <namespace>:<value> with a lowercase ASCII namespace"
    if not value or len(value) > 1000:
        return "ref value must be 1-1000 characters"
    if RE_SURROGATE.search(value):
        return "ref value contains an unpaired surrogate"
    if RE_CONTROL.search(value):
        return "ref value contains control characters"
    if unicodedata.normalize("NFC", value) != value:
        return "ref value is not NFC-normalised"
    return None


# ---------------------------------------------------------------------------------------
# Error aggregation (agent-report-v1.md)
# ---------------------------------------------------------------------------------------


def aggregate_error_counts(counts: dict[str, int]) -> dict[str, int]:
    """Reference algorithm: reduce a complete code->count map to at most 100 keys."""
    if OTHER_CODES in counts:
        raise ValueError("other-codes is reserved")
    if len(counts) <= 100:
        return dict(counts)
    reserved = [c for c in RESERVED_TRUNCATION_CODES if c in counts]
    others = sorted((c for c in counts if c not in RESERVED_TRUNCATION_CODES), key=lambda c: (-counts[c], c))
    keep = reserved + others[: 99 - len(reserved)]
    result = {c: counts[c] for c in keep}
    result[OTHER_CODES] = sum(counts[c] for c in counts if c not in result)
    return result


def order_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reference algorithm: reserved truncation errors first (in reserved order), then the
    rest sorted by (code, ref or "", message); at most 100 retained."""
    reserved = [e for c in RESERVED_TRUNCATION_CODES for e in errors if e["code"] == c]
    rest = sorted(
        (e for e in errors if e["code"] not in RESERVED_TRUNCATION_CODES),
        key=lambda e: (e["code"], e.get("ref", ""), e["message"]),
    )
    return (reserved + rest)[:100]


# ---------------------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------------------


class Problems:
    """Collects ASCII problem messages (each <= 300 chars) keyed by JSON path."""

    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, path: str, message: str) -> None:
        text = f"{path}: {message}".encode("ascii", "replace").decode("ascii")
        self.items.append(text[:300])

    def __bool__(self) -> bool:
        return bool(self.items)


def _keys(p: Problems, obj: Any, path: str, required: set[str], optional: set[str] = frozenset()) -> bool:
    if not isinstance(obj, dict):
        p.add(path, "must be an object")
        return False
    missing = required - obj.keys()
    for key in sorted(missing):
        p.add(path, f"missing required field {key!r}")
    for key in sorted(obj.keys() - required - optional):
        p.add(path, f"unknown field {key!r}")
    return not missing  # callers only inspect fields when all required ones are present


def _int(p: Problems, value: Any, path: str, minimum: int = 0) -> bool:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        p.add(path, f"must be an integer >= {minimum}")
        return False
    return True


def _text(p: Problems, value: Any, path: str, max_len: int, allow_newlines: bool = True) -> None:
    if not isinstance(value, str):
        p.add(path, "must be a string")
        return
    if len(value) > max_len:
        p.add(path, f"longer than {max_len} characters")
    if RE_SURROGATE.search(value):
        p.add(path, "contains an unpaired surrogate")
    pattern = RE_TEXT_FORBIDDEN if allow_newlines else RE_CONTROL
    if pattern.search(value):
        p.add(path, "contains control characters")


def _pattern(p: Problems, value: Any, path: str, regex: re.Pattern[str], what: str) -> bool:
    if not isinstance(value, str) or not regex.fullmatch(value):
        p.add(path, f"must be {what}")
        return False
    return True


def _timestamp(p: Problems, value: Any, path: str) -> datetime | None:
    if not isinstance(value, str) or not RE_TIMESTAMP.fullmatch(value):
        p.add(path, "must be a UTC timestamp YYYY-MM-DDTHH:MM:SS[.ffffff]Z")
        return None
    try:
        return datetime.fromisoformat(value[:-1])
    except ValueError:
        p.add(path, "is not a valid date/time")
        return None


def _no_path_hints(p: Problems, value: Any, path: str) -> None:
    if isinstance(value, str) and RE_ABSOLUTE_PATH_HINT.search(value):
        p.add(path, "appears to contain an absolute filesystem path (not permitted)")


def _enum(p: Problems, value: Any, path: str, allowed: tuple[str, ...]) -> bool:
    if value not in allowed:
        p.add(path, f"must be one of {', '.join(allowed)}")
        return False
    return True


# ---------------------------------------------------------------------------------------
# Agent report validation
# ---------------------------------------------------------------------------------------


def _validate_errors(p: Problems, report: dict[str, Any]) -> dict[str, int]:
    errors, total, counts = report.get("errors"), report.get("errors_total"), report.get("error_counts")
    ok_total = _int(p, total, "$.errors_total")
    if not isinstance(errors, list):
        p.add("$.errors", "must be an array")
        errors = []
    if len(errors) > 100:
        p.add("$.errors", "more than 100 items")
    for i, err in enumerate(errors):
        path = f"$.errors[{i}]"
        if not _keys(p, err, path, {"code", "message"}, {"ref"}):
            continue
        if _pattern(p, err["code"], f"{path}.code", RE_CODE, "a lowercase code of at most 64 characters"):
            if err["code"] == OTHER_CODES:
                p.add(f"{path}.code", "other-codes is reserved and cannot be used as an error code")
        _text(p, err["message"], f"{path}.message", 500)
        if "ref" in err and (reason := valid_ref(err["ref"])):
            p.add(f"{path}.ref", reason)
    if ok_total and len(errors) != min(100, total):
        p.add("$.errors", f"must contain exactly min(100, errors_total) = {min(100, total)} items")
    well_formed = [e for e in errors if isinstance(e, dict) and isinstance(e.get("code"), str)
                   and isinstance(e.get("message"), str)]
    if len(well_formed) == len(errors) and errors != order_errors(errors):
        p.add("$.errors", "not in the required order (reserved truncation codes first, then by code, ref, message)")

    if not isinstance(counts, dict):
        p.add("$.error_counts", "must be an object")
        return {}
    if len(counts) > 100:
        p.add("$.error_counts", "more than 100 keys")
    for code, n in counts.items():
        if code != OTHER_CODES and not RE_CODE.fullmatch(code):
            p.add("$.error_counts", f"invalid code {code!r}")
        _int(p, n, f"$.error_counts.{code}", 1)
    if OTHER_CODES in counts and len(counts) != 100:
        p.add("$.error_counts", "other-codes may only be used when 99 other codes are retained")
    if ok_total and all(isinstance(n, int) for n in counts.values()) and sum(counts.values()) != total:
        p.add("$.error_counts", "values must add up to errors_total")
    for i, err in enumerate(errors):
        code = err.get("code") if isinstance(err, dict) else None
        if isinstance(code, str) and code not in counts and OTHER_CODES not in counts:
            p.add(f"$.errors[{i}].code", "not present in error_counts")
    for code in RESERVED_TRUNCATION_CODES:
        if code in counts and not any(isinstance(e, dict) and e.get("code") == code for e in errors):
            p.add("$.errors", f"reserved code {code} counted but not listed")
    return counts if isinstance(counts, dict) else {}


def _validate_finding(p: Problems, f: Any, path: str, agent_name: str, counts: dict[str, int]) -> None:
    required = {
        "finding_id", "created_at", "rule_id", "severity", "observation", "assessment",
        "recommendation", "limitations", "evidence", "evidence_total", "evidence_refs_digest",
    }
    optional = {"evidence_details_omitted", "data_warnings", "data_warnings_total"}
    if not _keys(p, f, path, required, optional):
        return
    _timestamp(p, f["created_at"], f"{path}.created_at")
    rule_ok = _pattern(p, f["rule_id"], f"{path}.rule_id", RE_CODE, "a lowercase rule id of at most 64 characters")
    _enum(p, f["severity"], f"{path}.severity", ("low", "medium", "high"))
    for field in ("observation", "assessment", "recommendation", "limitations"):
        _text(p, f[field], f"{path}.{field}", 2000)

    evidence = f["evidence"]
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 500:
        p.add(f"{path}.evidence", "must be an array of 1-500 items")
        evidence = evidence if isinstance(evidence, list) else []
    refs: list[str] = []
    details_present = False
    for j, item in enumerate(evidence):
        ipath = f"{path}.evidence[{j}]"
        if not _keys(p, item, ipath, {"ref"}, {"timestamp", "details"}):
            continue
        if reason := valid_ref(item["ref"]):
            p.add(f"{ipath}.ref", reason)
        else:
            refs.append(item["ref"])
        if "timestamp" in item:
            _timestamp(p, item["timestamp"], f"{ipath}.timestamp")
        if "details" in item:
            details_present = True
            if not isinstance(item["details"], dict):
                p.add(f"{ipath}.details", "must be an object")
    if len(set(refs)) != len(refs):
        p.add(f"{path}.evidence", "evidence refs must be unique")

    total = f["evidence_total"]
    digest = f["evidence_refs_digest"]
    if _int(p, total, f"{path}.evidence_total", 1) and isinstance(evidence, list):
        if total < len(evidence):
            p.add(f"{path}.evidence_total", "smaller than the number of evidence items")
        elif total > len(evidence):
            if refs != canonical_refs(refs):
                p.add(f"{path}.evidence", "truncated evidence must be listed in canonical ref order")
            disclosed = len(evidence) == min(500, total)
            for_size = len(evidence) == min(100, total) and "evidence-truncated-for-size" in counts
            if not (disclosed or for_size):
                p.add(f"{path}.evidence", "truncated evidence must keep 500 items, or 100 with evidence-truncated-for-size")
    if not isinstance(digest, str) or not RE_HEX64.fullmatch(digest):
        p.add(f"{path}.evidence_refs_digest", "must be 64 lowercase hex characters")
    elif isinstance(total, int) and total == len(evidence) == len(refs) and evidence_refs_digest(refs) != digest:
        p.add(f"{path}.evidence_refs_digest", "does not match the evidence refs")
    digest_ok = isinstance(digest, str) and RE_HEX64.fullmatch(digest) is not None
    if rule_ok and digest_ok and f.get("finding_id") != finding_id(agent_name, f["rule_id"], digest):
        p.add(f"{path}.finding_id", "does not match agent name, rule_id and evidence_refs_digest")

    if "evidence_details_omitted" in f:
        if f["evidence_details_omitted"] is not True:
            p.add(f"{path}.evidence_details_omitted", "may only be true")
        if details_present:
            p.add(f"{path}.evidence", "details present although evidence_details_omitted is true")
        if "details-omitted-for-size" not in counts:
            p.add(f"{path}.evidence_details_omitted", "requires a details-omitted-for-size error")

    if ("data_warnings" in f) != ("data_warnings_total" in f):
        p.add(path, "data_warnings and data_warnings_total must appear together")
    if "data_warnings" in f:
        warnings = f["data_warnings"]
        if not isinstance(warnings, list) or len(warnings) > 50:
            p.add(f"{path}.data_warnings", "must be an array of at most 50 items")
            warnings = []
        for k, w in enumerate(warnings):
            wpath = f"{path}.data_warnings[{k}]"
            if not _keys(p, w, wpath, {"field", "refs", "refs_total", "warning"}):
                continue
            _pattern(p, w["field"], f"{wpath}.field", RE_FIELD, "a field name of at most 64 ASCII characters")
            if not isinstance(w["refs"], list) or len(w["refs"]) > 100:
                p.add(f"{wpath}.refs", "must be an array of at most 100 refs")
            else:
                for r in w["refs"]:
                    if reason := valid_ref(r):
                        p.add(f"{wpath}.refs", reason)
                if _int(p, w["refs_total"], f"{wpath}.refs_total", 1) and len(w["refs"]) != min(100, w["refs_total"]):
                    p.add(f"{wpath}.refs", "must contain exactly min(100, refs_total) refs")
            _text(p, w["warning"], f"{wpath}.warning", 500)
        if _int(p, f["data_warnings_total"], f"{path}.data_warnings_total", 1) and len(warnings) != min(
            50, f["data_warnings_total"]
        ):
            p.add(f"{path}.data_warnings", "must contain exactly min(50, data_warnings_total) items")


def validate_agent_report(report: Any, size_bytes: int | None = None) -> list[str]:
    """Validate structure and every invariant of borealis-agent-report/1. Returns problems."""
    p = Problems()
    if size_bytes is not None and size_bytes > MAX_AGENT_REPORT_BYTES:
        p.add("$", "report exceeds 10 MiB")
    required = {"standard", "agent", "run", "source", "status", "errors", "errors_total",
                "error_counts", "findings", "findings_total"}
    if not _keys(p, report, "$", required, {"extensions"}):
        return p.items
    if report["standard"] != AGENT_STANDARD:
        p.add("$.standard", f"must be {AGENT_STANDARD!r}")
    agent_name = ""
    if _keys(p, report["agent"], "$.agent", {"name", "version"}):
        if _pattern(p, report["agent"]["name"], "$.agent.name", RE_AGENT_NAME, "a lowercase agent name"):
            agent_name = report["agent"]["name"]
        version = report["agent"]["version"]
        if not isinstance(version, str) or not 1 <= len(version) <= 32 or not RE_PRINTABLE_ASCII.fullmatch(version):
            p.add("$.agent.version", "must be 1-32 printable ASCII characters")
    if _keys(p, report["run"], "$.run", {"id", "started_at", "finished_at"}):
        _pattern(p, report["run"]["id"], "$.run.id", RE_UUID4, "a lowercase UUID v4")
        start = _timestamp(p, report["run"]["started_at"], "$.run.started_at")
        end = _timestamp(p, report["run"]["finished_at"], "$.run.finished_at")
        if start and end and end < start:
            p.add("$.run.finished_at", "is earlier than started_at")
    if _keys(p, report["source"], "$.source", {"type", "description", "scope"}):
        src = report["source"]
        _pattern(p, src["type"], "$.source.type", RE_TOKEN, "an ASCII token of at most 64 characters")
        _text(p, src["description"], "$.source.description", 500)
        _no_path_hints(p, src["description"], "$.source.description")
        scope = src["scope"]
        if not isinstance(scope, list) or len(scope) > 100:
            p.add("$.source.scope", "must be an array of at most 100 items")
        else:
            for i, item in enumerate(scope):
                ipath = f"$.source.scope[{i}]"
                if _keys(p, item, ipath, {"kind", "id"}, {"count"}):
                    _pattern(p, item["kind"], f"{ipath}.kind", RE_TOKEN, "an ASCII token")
                    _pattern(p, item["id"], f"{ipath}.id", RE_TOKEN, "an ASCII token")
                    if "count" in item:
                        _int(p, item["count"], f"{ipath}.count")
    if "extensions" in report and not isinstance(report["extensions"], dict):
        p.add("$.extensions", "must be an object")

    status_ok = _enum(p, report["status"], "$.status", ("ok", "partial", "error"))
    counts = _validate_errors(p, report)
    total_errors = report["errors_total"] if isinstance(report["errors_total"], int) else None
    if status_ok and total_errors is not None:
        if report["status"] == "ok" and total_errors != 0:
            p.add("$.status", "ok requires errors_total == 0")
        if report["status"] in ("partial", "error") and total_errors < 1:
            p.add("$.status", f"{report['status']} requires errors_total >= 1")
    if "report-too-large" in counts and report["status"] != "error":
        p.add("$.status", "report-too-large requires status error")
    loss_codes = [c for c in ("findings-truncated", "evidence-truncated-for-size", "details-omitted-for-size")
                  if c in counts]
    if loss_codes and report["status"] == "ok":
        p.add("$.status", "loss truncation requires status partial or error")

    findings = report["findings"]
    if not isinstance(findings, list) or len(findings) > 1000:
        p.add("$.findings", "must be an array of at most 1000 items")
        findings = findings if isinstance(findings, list) else []
    for i, f in enumerate(findings):
        _validate_finding(p, f, f"$.findings[{i}]", agent_name, counts)
    ids = [f.get("finding_id") for f in findings if isinstance(f, dict) and isinstance(f.get("finding_id"), str)]
    if len(ids) != len(set(ids)):
        p.add("$.findings", "duplicate finding_id values (findings must be unique by rule and evidence)")
    if _int(p, report["findings_total"], "$.findings_total"):
        truncated = report["findings_total"] != len(findings)
        if report["findings_total"] < len(findings):
            p.add("$.findings_total", "smaller than the number of findings")
        if truncated != ("findings-truncated" in counts):
            p.add("$.findings_total", "findings-truncated must be reported exactly when findings were dropped")
        if truncated:
            ranked = sorted(
                (f for f in findings if isinstance(f, dict)),
                key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 9), str(f.get("finding_id"))),
            )
            if ranked != findings:
                p.add("$.findings", "truncated findings must be in ranking order (severity, finding_id)")
    if "evidence-truncated-for-size" in counts and not any(
        isinstance(f, dict) and isinstance(f.get("evidence"), list)
        and isinstance(f.get("evidence_total"), int) and len(f["evidence"]) < min(500, f["evidence_total"])
        for f in findings
    ) and findings:
        p.add("$.errors", "evidence-truncated-for-size reported but no evidence list was cut for size")
    if "details-omitted-for-size" in counts and findings and not any(
        isinstance(f, dict) and f.get("evidence_details_omitted") is True for f in findings
    ):
        p.add("$.errors", "details-omitted-for-size reported but no finding has evidence_details_omitted")
    return p.items


# ---------------------------------------------------------------------------------------
# Node report validation
# ---------------------------------------------------------------------------------------


def agent_outcome(validation_result: str, report: dict[str, Any] | None, status: str | None) -> str:
    if validation_result != "valid" or not isinstance(status, str):
        return "failed"
    return {"ok": "ok", "partial": "degraded"}.get(status, "failed")


def node_outcome(agent_outcomes: list[str]) -> str:
    if agent_outcomes and all(o == "ok" for o in agent_outcomes):
        return "ok"
    if not any(o in ("ok", "degraded") for o in agent_outcomes):
        return "failed"
    return "degraded"


def validate_node_report(report: Any, size_bytes: int | None = None) -> list[str]:
    p = Problems()
    if size_bytes is not None and size_bytes > MAX_NODE_REPORT_BYTES:
        p.add("$", "node report exceeds 64 MiB")
    if not _keys(p, report, "$", {"standard", "node", "run", "outcome", "complete", "agents"}):
        return p.items
    if report["standard"] != NODE_STANDARD:
        p.add("$.standard", f"must be {NODE_STANDARD!r}")
    if _keys(p, report["node"], "$.node", {"name", "version"}):
        if report["node"]["name"] != "borealis-node":
            p.add("$.node.name", "must be 'borealis-node'")
        v = report["node"]["version"]
        if not isinstance(v, str) or not 1 <= len(v) <= 32 or not RE_PRINTABLE_ASCII.fullmatch(v):
            p.add("$.node.version", "must be 1-32 printable ASCII characters")
    if _keys(p, report["run"], "$.run", {"id", "started_at", "finished_at"}):
        _pattern(p, report["run"]["id"], "$.run.id", RE_UUID4, "a lowercase UUID v4")
        _timestamp(p, report["run"]["started_at"], "$.run.started_at")
        _timestamp(p, report["run"]["finished_at"], "$.run.finished_at")
    _enum(p, report["outcome"], "$.outcome", ("ok", "degraded", "failed"))
    if not isinstance(report["complete"], bool):
        p.add("$.complete", "must be a boolean")

    agents = report["agents"]
    if not isinstance(agents, list) or not 1 <= len(agents) <= 32:
        p.add("$.agents", "must be an array of 1-32 items")
        return p.items
    names: list[str] = []
    outcomes: list[str] = []
    any_omitted = False
    for i, a in enumerate(agents):
        path = f"$.agents[{i}]"
        required = {"config_name", "expected_name", "outcome", "execution", "validation", "diagnostic",
                    "report_embedding", "report", "report_summary"}
        if not _keys(p, a, path, required):
            continue
        if _pattern(p, a["config_name"], f"{path}.config_name", RE_CONFIG_NAME, "a safe config name"):
            names.append(a["config_name"])
        _pattern(p, a["expected_name"], f"{path}.expected_name", RE_AGENT_NAME, "an agent name")
        _enum(p, a["outcome"], f"{path}.outcome", ("ok", "degraded", "failed"))
        outcomes.append(a["outcome"])

        ex = a["execution"]
        exec_keys = {"started_at", "finished_at", "exit_code", "timed_out", "killed", "stdout_bytes",
                     "output_too_large", "launch_error"}
        if _keys(p, ex, f"{path}.execution", exec_keys):
            _timestamp(p, ex["started_at"], f"{path}.execution.started_at")
            _timestamp(p, ex["finished_at"], f"{path}.execution.finished_at")
            if ex["exit_code"] is not None and (not isinstance(ex["exit_code"], int) or isinstance(ex["exit_code"], bool)):
                p.add(f"{path}.execution.exit_code", "must be an integer or null")
            for flag in ("timed_out", "killed", "output_too_large"):
                if not isinstance(ex[flag], bool):
                    p.add(f"{path}.execution.{flag}", "must be a boolean")
            _int(p, ex["stdout_bytes"], f"{path}.execution.stdout_bytes")
            if ex["launch_error"] is not None:
                _enum(p, ex["launch_error"], f"{path}.execution.launch_error", LAUNCH_ERRORS)

        val = a["validation"]
        result = None
        if _keys(p, val, f"{path}.validation", {"result", "problems", "problems_total"}):
            if _enum(p, val["result"], f"{path}.validation.result", ("valid", "invalid", "not-run")):
                result = val["result"]
            probs = val["problems"]
            if not isinstance(probs, list) or len(probs) > 50:
                p.add(f"{path}.validation.problems", "must be an array of at most 50 items")
            else:
                for prob in probs:
                    if not isinstance(prob, str) or not 1 <= len(prob) <= 300 or not RE_PRINTABLE_ASCII.fullmatch(prob):
                        p.add(f"{path}.validation.problems", "items must be 1-300 printable ASCII characters")
                        break
                if _int(p, val["problems_total"], f"{path}.validation.problems_total") and len(probs) != min(
                    50, val["problems_total"]
                ):
                    p.add(f"{path}.validation.problems", "must contain exactly min(50, problems_total) items")
                if result == "valid" and val["problems_total"] != 0:
                    p.add(f"{path}.validation", "a valid report has no problems")
                if result == "invalid" and val["problems_total"] == 0:
                    p.add(f"{path}.validation", "an invalid report must list problems")

        if a["diagnostic"] is not None:
            _text(p, a["diagnostic"], f"{path}.diagnostic", 2000)
            if isinstance(a["diagnostic"], str) and "\x1b" in a["diagnostic"]:
                p.add(f"{path}.diagnostic", "must be sanitised (no escape sequences)")

        embedding = a["report_embedding"]
        _enum(p, embedding, f"{path}.report_embedding", ("embedded", "omitted-for-size", "none"))
        status = None
        if embedding == "embedded":
            if result != "valid" or a["report"] is None:
                p.add(path, "embedded requires a valid report")
            else:
                for prob in validate_agent_report(a["report"]):
                    p.add(f"{path}.report", prob)
                if isinstance(a["report"], dict):
                    status = a["report"].get("status")
                    agent = a["report"].get("agent")
                    if not isinstance(agent, dict) or agent.get("name") != a["expected_name"]:
                        p.add(f"{path}.report.agent.name", "does not match expected_name")
            if a["report_summary"] is not None:
                p.add(f"{path}.report_summary", "must be null when the report is embedded")
        elif embedding == "omitted-for-size":
            any_omitted = True
            if result != "valid" or a["report"] is not None:
                p.add(path, "omitted-for-size requires a valid report and report: null")
            s = a["report_summary"]
            summary_keys = {"bytes", "status", "findings_total", "counts_by_severity", "finding_ids",
                            "finding_ids_total", "saved_as"}
            if _keys(p, s, f"{path}.report_summary", summary_keys):
                _int(p, s["bytes"], f"{path}.report_summary.bytes")
                if _enum(p, s["status"], f"{path}.report_summary.status", ("ok", "partial", "error")):
                    status = s["status"]
                _int(p, s["findings_total"], f"{path}.report_summary.findings_total")
                if _keys(p, s["counts_by_severity"], f"{path}.report_summary.counts_by_severity",
                         {"low", "medium", "high"}):
                    for k in ("low", "medium", "high"):
                        _int(p, s["counts_by_severity"][k], f"{path}.report_summary.counts_by_severity.{k}")
                ids = s["finding_ids"]
                if not isinstance(ids, list) or len(ids) > 200 or not all(
                    isinstance(x, str) and len(x) <= 98 and RE_PRINTABLE_ASCII.fullmatch(x) for x in ids
                ):
                    p.add(f"{path}.report_summary.finding_ids", "must be at most 200 ASCII ids of at most 98 characters")
                elif _int(p, s["finding_ids_total"], f"{path}.report_summary.finding_ids_total") and len(ids) != min(
                    200, s["finding_ids_total"]
                ):
                    p.add(f"{path}.report_summary.finding_ids", "must contain exactly min(200, finding_ids_total) ids")
                if s["saved_as"] is not None and s["saved_as"] != f"{a['config_name']}.json":
                    p.add(f"{path}.report_summary.saved_as", "must be null or '<config_name>.json' (a file name, never a path)")
        else:
            if a["report"] is not None or a["report_summary"] is not None:
                p.add(path, "report_embedding none requires report and report_summary to be null")
            if result == "valid":
                p.add(path, "a valid report must be embedded or omitted-for-size")
        if result is not None and a["outcome"] != agent_outcome(result, a["report"], status):
            p.add(f"{path}.outcome", "inconsistent with validation result and agent status")

    if len(names) != len(set(names)):
        p.add("$.agents", "config_name values must be unique")
    if isinstance(report["complete"], bool) and report["complete"] == any_omitted:
        p.add("$.complete", "must be false exactly when a report was omitted for size")
    if outcomes and report["outcome"] != node_outcome(outcomes):
        p.add("$.outcome", "inconsistent with the agent outcomes")
    return p.items


# ---------------------------------------------------------------------------------------
# Maximum-envelope node report (worst case for every bounded field)
# ---------------------------------------------------------------------------------------


def max_envelope_node_report() -> dict[str, Any]:
    """32 agent entries with every Node-controlled field at its limit, using characters
    that serialise to the most bytes. Report bodies are omitted-for-size so only the
    envelope is measured."""
    worst = chr(0x1F600)  # one code point, 4 UTF-8 bytes: the most bytes per counted character
    agents = []
    for i in range(32):
        name = f"a{i:02d}" + "x" * 28  # 32 chars
        agents.append({
            "config_name": name,
            "expected_name": "n" * 40,
            "outcome": "failed",
            "execution": {
                "started_at": "2026-11-20T09:00:00.000000Z", "finished_at": "2026-11-20T09:00:01.000000Z",
                "exit_code": -(2**31), "timed_out": True, "killed": True, "stdout_bytes": 10 * 1024 * 1024,
                "output_too_large": True, "launch_error": "describe-mismatch",
            },
            "validation": {"result": "valid", "problems": [], "problems_total": 0},
            "diagnostic": worst * 2000,  # 2000 characters, 8000 bytes
            "report_embedding": "omitted-for-size",
            "report": None,
            "report_summary": {
                "bytes": 10 * 1024 * 1024, "status": "error", "findings_total": 1000,
                "counts_by_severity": {"low": 1000, "medium": 1000, "high": 1000},
                "finding_ids": ["n" * 40 + ":" + "r" * 40 + ":" + "0" * 16 for _ in range(200)],
                "finding_ids_total": 1000,
                "saved_as": f"{name}.json",
            },
        })
    # One entry with maximum problems instead (an invalid report).
    for entry in agents[:16]:
        entry["validation"] = {"result": "invalid", "problems": ["p" * 300] * 50, "problems_total": 10**6}
        entry["report_embedding"] = "none"
        entry["report_summary"] = None
    return {
        "standard": NODE_STANDARD,
        "node": {"name": "borealis-node", "version": "v" * 32},
        "run": {"id": "00000000-0000-4000-8000-000000000000",
                "started_at": "2026-11-20T09:00:00.000000Z", "finished_at": "2026-11-20T09:00:01.000000Z"},
        "outcome": "failed",
        "complete": False,
        "agents": agents,
    }


# ---------------------------------------------------------------------------------------
# Test vectors
# ---------------------------------------------------------------------------------------


def verify_vectors(path: Path) -> list[str]:
    vectors = strict_loads(path.read_bytes())
    failures: list[str] = []

    for v in vectors["canonical_json"]:
        try:
            # Inputs are JSON text parsed leniently, because some deliberately contain
            # floats or out-of-range integers that canonical JSON must reject.
            out = canonical_json(json.loads(v["input_json"])).decode("utf-8")
            if "error" in v:
                failures.append(f"canonical_json {v['name']}: expected an error")
            elif out != v["output"] or sha256_hex(out.encode("utf-8")) != v["sha256"]:
                failures.append(f"canonical_json {v['name']}: got {out!r}")
        except CanonicalJsonError:
            if "error" not in v:
                failures.append(f"canonical_json {v['name']}: unexpected error")

    for v in vectors["strict_parsing"]:
        try:
            strict_loads(bytes.fromhex(v["input_hex"]))
            if v["valid"] is False:
                failures.append(f"strict_parsing {v['name']}: expected rejection")
        except StrictJsonError:
            if v["valid"] is True:
                failures.append(f"strict_parsing {v['name']}: unexpected rejection")

    for v in vectors["finding_ids"]:
        digest = evidence_refs_digest(v["refs"])
        if canonical_refs(v["refs"]) != v["canonical_refs"]:
            failures.append(f"finding_ids {v['name']}: canonical refs differ")
        if digest != v["evidence_refs_digest"]:
            failures.append(f"finding_ids {v['name']}: digest {digest}")
        if finding_id(v["agent"], v["rule_id"], digest) != v["finding_id"]:
            failures.append(f"finding_ids {v['name']}: finding_id differs")

    for v in vectors["error_aggregation"]:
        counts = {c: n for c, n in v["counts"].items()} if "counts" in v else _generated_counts(v["generate"])
        if aggregate_error_counts(counts) != v["expected_error_counts"]:
            failures.append(f"error_aggregation {v['name']}: error_counts differ")
        if sum(v["expected_error_counts"].values()) != sum(counts.values()):
            failures.append(f"error_aggregation {v['name']}: sum differs from errors_total")

    for v in vectors["reports"]:
        problems = validate_agent_report(v["report"]) if v["kind"] == "agent" else validate_node_report(v["report"])
        if v["valid"] and problems:
            failures.append(f"reports {v['name']}: unexpected problems {problems[:3]}")
        if not v["valid"]:
            if not problems:
                failures.append(f"reports {v['name']}: expected problems")
            elif v.get("expect_problem") and not any(v["expect_problem"] in x for x in problems):
                failures.append(f"reports {v['name']}: expected a problem containing {v['expect_problem']!r}, got {problems[:3]}")

    envelope = max_envelope_node_report()
    size = len(json.dumps(envelope, ensure_ascii=False).encode("utf-8"))
    if size > NODE_ENVELOPE_RESERVE:
        failures.append(f"max envelope is {size} bytes, above the 8 MiB reserve")
    if problems := validate_node_report(envelope):
        failures.append(f"max envelope invalid: {problems[:3]}")
    return failures


def _generated_counts(spec: dict[str, Any]) -> dict[str, int]:
    """Deterministic generator used by large aggregation vectors."""
    counts = {f"{spec['prefix']}-{i:03d}": spec["base"] + (i % spec["modulo"]) for i in range(spec["distinct"])}
    counts.update(spec.get("extra", {}))
    return counts


# ---------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] in ("agent", "node"):
        data = Path(argv[1]).read_bytes()
        try:
            report = strict_loads(data)
        except StrictJsonError as exc:
            print(f"INVALID: {exc}")
            return 1
        problems = (validate_agent_report if argv[0] == "agent" else validate_node_report)(report, len(data))
        for problem in problems:
            print(problem)
        print("VALID" if not problems else f"INVALID ({len(problems)} problems)")
        return 0 if not problems else 1
    if argv[:1] == ["vectors"]:
        failures = verify_vectors(Path(__file__).resolve().parent.parent / "test-vectors-v1.json")
        for failure in failures:
            print(failure)
        print("ALL VECTORS PASS" if not failures else f"{len(failures)} FAILURES")
        return 0 if not failures else 1
    if len(argv) == 2 and argv[0] == "max-envelope":
        Path(argv[1]).write_bytes(json.dumps(max_envelope_node_report(), ensure_ascii=False).encode("utf-8"))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
