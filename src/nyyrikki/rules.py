"""Deterministic detection rules over Windows Security events.

Each rule takes the full list of parsed events and returns findings.
Thresholds are fixed constants; see docs/detections.md for rationale and limitations.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Callable

from nyyrikki.events import Event
from nyyrikki.findings import Evidence, Finding

FAILED_LOGON = 4625
SUCCESSFUL_LOGON = 4624
ACCOUNT_CREATED = 4720
GROUP_MEMBER_ADDED = (4728, 4732, 4756)  # global, local, universal security groups
AUDIT_LOG_CLEARED = 1102
EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"

BURST_THRESHOLD = 10
BURST_WINDOW = timedelta(minutes=5)
SUCCESS_AFTER_BURST_WINDOW = timedelta(minutes=10)

PRIVILEGED_SIDS = {"S-1-5-32-544"}  # BUILTIN\Administrators
PRIVILEGED_RID_SUFFIXES = ("-512", "-518", "-519")  # Domain, Schema, Enterprise Admins
PRIVILEGED_GROUP_NAMES = {"administrators", "domain admins", "schema admins", "enterprise admins"}

LOGON_FIELDS = ("TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "WorkstationName")
FAILED_LOGON_FIELDS = LOGON_FIELDS + ("Status", "SubStatus")


def _account(event: Event) -> str:
    return event.get("TargetUserName").lower()


def _failed_logon_bursts(events: list[Event]) -> list[list[Event]]:
    """Group failed logons per account and return each run of >= BURST_THRESHOLD within BURST_WINDOW."""
    by_account: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.event_id == FAILED_LOGON:
            by_account[_account(event)].append(event)

    bursts: list[list[Event]] = []
    for account_events in by_account.values():
        fails = sorted(account_events, key=lambda e: (e.time_created, e.record_id))
        i = j = 0
        while i < len(fails):
            j = max(j, i)
            while j + 1 < len(fails) and fails[j + 1].time_created - fails[i].time_created <= BURST_WINDOW:
                j += 1
            if j - i + 1 >= BURST_THRESHOLD:
                bursts.append(fails[i : j + 1])
                i = j + 1
            else:
                i += 1
    return sorted(bursts, key=lambda burst: burst[0].time_created)


def failed_logon_burst(events: list[Event]) -> list[Finding]:
    findings = []
    for burst in _failed_logon_bursts(events):
        account = burst[0].get("TargetUserName") or "(unknown)"
        span = burst[-1].time_created - burst[0].time_created
        findings.append(
            Finding(
                rule_id="failed-logon-burst",
                severity="medium",
                assessment="Potentially suspicious: repeated failed logons can indicate password guessing.",
                recommendation="Review the source of the logon attempts and whether the account owner expected them.",
                observation=(
                    f"{len(burst)} failed logons (event 4625) for account '{account}' "
                    f"within {int(span.total_seconds())} seconds."
                ),
                evidence=[Evidence.from_event(e, FAILED_LOGON_FIELDS) for e in burst],
                limitations=(
                    "Mistyped or cached passwords and misconfigured services also produce bursts. "
                    "Accounts are matched by user name only. Requires failed-logon auditing."
                ),
            )
        )
    return findings


def failed_then_success(events: list[Event]) -> list[Finding]:
    successes = sorted(
        (e for e in events if e.event_id == SUCCESSFUL_LOGON),
        key=lambda e: (e.time_created, e.record_id),
    )
    findings = []
    for burst in _failed_logon_bursts(events):
        account = _account(burst[0])
        end = burst[-1].time_created
        success = next(
            (
                s
                for s in successes
                if _account(s) == account and end < s.time_created <= end + SUCCESS_AFTER_BURST_WINDOW
            ),
            None,
        )
        if success is None:
            continue
        name = burst[0].get("TargetUserName") or "(unknown)"
        findings.append(
            Finding(
                rule_id="failed-then-success",
                severity="high",
                assessment="Potentially suspicious: a success after many failures can indicate a guessed password.",
                recommendation="Confirm with the account owner that the logon was theirs; review the logon source.",
                observation=(
                    f"Account '{name}' logged on successfully (event 4624) "
                    f"{int((success.time_created - end).total_seconds())} seconds after "
                    f"{len(burst)} failed logons."
                ),
                evidence=[Evidence.from_event(e, FAILED_LOGON_FIELDS) for e in burst]
                + [Evidence.from_event(success, LOGON_FIELDS)],
                limitations=(
                    "A user who mistypes a password repeatedly and then gets it right matches this rule. "
                    "Accounts are matched by user name only."
                ),
            )
        )
    return findings


def account_created(events: list[Event]) -> list[Finding]:
    fields = ("TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserName", "SubjectDomainName")
    return [
        Finding(
            rule_id="account-created",
            severity="medium",
            assessment="Potentially suspicious if the account creation was not planned.",
            recommendation="Confirm the new account was created intentionally by an authorised administrator.",
            observation=(
                f"Account '{e.get('TargetUserName')}' was created by '{e.get('SubjectUserName')}' (event 4720)."
            ),
            evidence=[Evidence.from_event(e, fields)],
            limitations="Legitimate administration creates accounts too; review whether the change was expected.",
        )
        for e in events
        if e.event_id == ACCOUNT_CREATED
    ]


def _is_privileged_group(event: Event) -> bool:
    sid = event.get("TargetSid")
    return (
        sid in PRIVILEGED_SIDS
        or sid.endswith(PRIVILEGED_RID_SUFFIXES)
        or event.get("TargetUserName").lower() in PRIVILEGED_GROUP_NAMES
    )


def privileged_group_add(events: list[Event]) -> list[Finding]:
    fields = ("MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserName")
    return [
        Finding(
            rule_id="privileged-group-add",
            severity="high",
            assessment="Potentially suspicious: adding members to privileged groups grants administrative control.",
            recommendation="Confirm the membership change was authorised and is still needed.",
            observation=(
                f"'{e.get('MemberName') or e.get('MemberSid')}' was added to privileged group "
                f"'{e.get('TargetUserName')}' by '{e.get('SubjectUserName')}' (event {e.event_id})."
            ),
            evidence=[Evidence.from_event(e, fields)],
            limitations=(
                "Only a fixed list of well-known privileged groups is checked. "
                "Legitimate administration also adds members."
            ),
        )
        for e in events
        if e.event_id in GROUP_MEMBER_ADDED and _is_privileged_group(e)
    ]


def audit_log_cleared(events: list[Event]) -> list[Finding]:
    fields = ("SubjectUserName", "SubjectDomainName", "SubjectUserSid")
    return [
        Finding(
            rule_id="audit-log-cleared",
            severity="high",
            assessment="Potentially suspicious: clearing the audit log can hide earlier activity.",
            recommendation="Confirm who cleared the log and why; check other sources for the missing period.",
            observation=f"The Security log was cleared by '{e.get('SubjectUserName')}' (event 1102).",
            evidence=[Evidence.from_event(e, fields)],
            limitations="Administrators sometimes clear logs legitimately. Events before the clear are not available.",
        )
        for e in events
        if e.event_id == AUDIT_LOG_CLEARED and e.provider == EVENTLOG_PROVIDER
    ]


RULES: tuple[Callable[[list[Event]], list[Finding]], ...] = (
    failed_logon_burst,
    failed_then_success,
    account_created,
    privileged_group_add,
    audit_log_cleared,
)


def run_rules(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(events))
    return findings
