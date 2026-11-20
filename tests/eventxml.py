"""Build synthetic Windows event XML for tests. All data produced here is simulated."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape, quoteattr

SECURITY = "Microsoft-Windows-Security-Auditing"
EVENTLOG = "Microsoft-Windows-Eventlog"
BASE_TIME = datetime(2026, 11, 20, 9, 0, 0, tzinfo=timezone.utc)


def ts(seconds: float) -> str:
    """Windows-style SystemTime string, `seconds` after BASE_TIME, with 7 fractional digits."""
    t = BASE_TIME + timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}0Z"


def event(
    record_id: int,
    event_id: int,
    seconds: float = 0,
    data: dict[str, str] | None = None,
    *,
    provider: str = SECURITY,
    computer: str = "WS01.example.test",
    user_data: tuple[str, dict[str, str]] | None = None,
) -> str:
    body = ""
    if data is not None:
        items = "".join(
            f"<Data Name={quoteattr(k)}>{escape(v)}</Data>" for k, v in data.items()
        )
        body = f"<EventData>{items}</EventData>"
    if user_data is not None:
        name, fields = user_data
        items = "".join(f"<{k}>{escape(v)}</{k}>" for k, v in fields.items())
        body += f'<UserData><{name} xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">{items}</{name}></UserData>'
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}"/><EventID>{event_id}</EventID>'
        f'<TimeCreated SystemTime="{ts(seconds)}"/>'
        f"<EventRecordID>{record_id}</EventRecordID><Channel>Security</Channel>"
        f"<Computer>{computer}</Computer></System>{body}</Event>"
    )


def failed_logon(record_id: int, seconds: float, user: str = "alice", ip: str = "192.0.2.10") -> str:
    return event(
        record_id,
        4625,
        seconds,
        {
            "TargetUserName": user,
            "TargetDomainName": "WS01",
            "LogonType": "3",
            "IpAddress": ip,
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a",
        },
    )


def successful_logon(record_id: int, seconds: float, user: str = "alice", ip: str = "192.0.2.10") -> str:
    return event(
        record_id,
        4624,
        seconds,
        {"TargetUserName": user, "TargetDomainName": "WS01", "LogonType": "3", "IpAddress": ip},
    )


def account_created(record_id: int, seconds: float, user: str = "svc-backup2") -> str:
    return event(
        record_id,
        4720,
        seconds,
        {
            "TargetUserName": user,
            "TargetDomainName": "WS01",
            "TargetSid": "S-1-5-21-1-2-3-1010",
            "SubjectUserName": "admin",
            "SubjectDomainName": "WS01",
        },
    )


def group_add(
    record_id: int,
    seconds: float,
    group: str = "Administrators",
    group_sid: str = "S-1-5-32-544",
    event_id: int = 4732,
) -> str:
    return event(
        record_id,
        event_id,
        seconds,
        {
            "MemberName": "-",
            "MemberSid": "S-1-5-21-1-2-3-1010",
            "TargetUserName": group,
            "TargetDomainName": "Builtin",
            "TargetSid": group_sid,
            "SubjectUserName": "admin",
        },
    )


def log_cleared(record_id: int, seconds: float, provider: str = EVENTLOG) -> str:
    return event(
        record_id,
        1102,
        seconds,
        provider=provider,
        user_data=("LogFileCleared", {"SubjectUserName": "admin", "SubjectDomainName": "WS01"}),
    )
