"""Parse Windows event XML (as produced by wevtutil or Event Viewer) into Event records.

Input is treated as untrusted data. Documents containing a DTD are rejected,
so no entity expansion or external entity resolution can take place.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS = {"e": EVENT_NS}

_XML_DECL = re.compile(r"<\?xml[^>]*\?>")
_TIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$"
)


class ParseError(ValueError):
    """Raised when input cannot be parsed as Windows event XML."""


@dataclass(frozen=True)
class Event:
    record_id: int
    event_id: int
    provider: str
    time_created: datetime
    computer: str
    data: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str:
        return self.data.get(name, "")


def parse_time(value: str) -> datetime:
    """Parse a Windows SystemTime value such as 2026-11-20T13:35:20.1234567Z.

    Values without an offset are treated as UTC, which is how Windows records SystemTime.
    """
    match = _TIME.match(value.strip())
    if not match:
        raise ParseError(f"unrecognised timestamp: {value!r}")
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    if offset in (None, "Z"):
        tz = timezone.utc
    else:
        sign = 1 if offset[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6])))
    return datetime(
        int(year), int(month), int(day), int(hour), int(minute), int(second), micro, tzinfo=tz
    )


def _decode(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_event(elem: ET.Element, index: int) -> Event:
    system = elem.find("e:System", _NS)
    if system is None:
        raise ParseError(f"event #{index}: missing System element")

    def text(path: str) -> str:
        node = system.find(path, _NS)
        return (node.text or "").strip() if node is not None else ""

    provider_node = system.find("e:Provider", _NS)
    time_node = system.find("e:TimeCreated", _NS)
    try:
        record_id = int(text("e:EventRecordID"))
        event_id = int(text("e:EventID"))
    except ValueError:
        raise ParseError(f"event #{index}: missing or invalid EventRecordID/EventID") from None
    if time_node is None or not time_node.get("SystemTime"):
        raise ParseError(f"event #{index}: missing TimeCreated SystemTime")

    data: dict[str, str] = {}
    event_data = elem.find("e:EventData", _NS)
    if event_data is not None:
        for node in event_data.findall("e:Data", _NS):
            name = node.get("Name")
            if name:
                data[name] = (node.text or "").strip()
    user_data = elem.find("e:UserData", _NS)
    if user_data is not None:
        for container in user_data:
            for node in container:
                data[_local(node.tag)] = (node.text or "").strip()

    return Event(
        record_id=record_id,
        event_id=event_id,
        provider=provider_node.get("Name", "") if provider_node is not None else "",
        time_created=parse_time(time_node.get("SystemTime", "")),
        computer=text("e:Computer"),
        data=data,
    )


def parse_events(text: str) -> list[Event]:
    """Parse event XML text: either a bare sequence of <Event> elements or an <Events> document."""
    if "<!DOCTYPE" in text.upper():
        raise ParseError("documents containing a DTD are not supported")
    body = _XML_DECL.sub("", text)
    try:
        root = ET.fromstring(f"<nyyrikki-input>{body}</nyyrikki-input>")
    except ET.ParseError as exc:
        raise ParseError(f"invalid XML: {exc}") from None
    return [
        _parse_event(elem, i)
        for i, elem in enumerate(root.iter(f"{{{EVENT_NS}}}Event"), start=1)
    ]


def load_events(path: str | Path) -> list[Event]:
    """Read and parse an event XML file. Handles UTF-8 and UTF-16 (PowerShell 5.1 redirection)."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc.strerror or exc}") from None
    try:
        text = _decode(raw)
    except UnicodeDecodeError:
        raise ParseError(f"{path}: file is neither UTF-8 nor UTF-16 text") from None
    return parse_events(text)
