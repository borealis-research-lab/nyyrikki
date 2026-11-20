from datetime import datetime, timezone

import pytest

import eventxml as ex
from nyyrikki.events import ParseError, load_events, parse_events, parse_time


def test_parses_bare_event_sequence_from_wevtutil():
    events = parse_events(ex.failed_logon(1, 0) + "\r\n" + ex.successful_logon(2, 30))
    assert [(e.record_id, e.event_id) for e in events] == [(1, 4625), (2, 4624)]
    assert events[0].get("TargetUserName") == "alice"
    assert events[0].provider == ex.SECURITY
    assert events[0].computer == "WS01.example.test"


def test_parses_event_viewer_document_with_declaration_and_root():
    text = '<?xml version="1.0" encoding="UTF-8"?><Events>' + ex.account_created(7, 0) + "</Events>"
    [event] = parse_events(text)
    assert event.event_id == 4720
    assert event.get("TargetUserName") == "svc-backup2"


def test_reads_user_data_fields():
    [event] = parse_events(ex.log_cleared(5, 0))
    assert event.get("SubjectUserName") == "admin"


def test_load_events_handles_utf16_from_powershell_redirection(tmp_path):
    path = tmp_path / "security.xml"
    path.write_bytes(ex.failed_logon(1, 0).encode("utf-16"))  # includes BOM
    assert load_events(path)[0].record_id == 1


def test_empty_input_yields_no_events():
    assert parse_events("") == []


@pytest.mark.parametrize(
    "text",
    [
        "<Event><unclosed>",
        ex.failed_logon(1, 0).replace("<EventRecordID>1</EventRecordID>", ""),
        ex.failed_logon(1, 0).replace("SystemTime=", "Other="),
    ],
)
def test_malformed_input_raises_parse_error(text):
    with pytest.raises(ParseError):
        parse_events(text)


def test_rejects_dtd_so_entities_are_never_expanded():
    text = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]>' + ex.failed_logon(1, 0)
    with pytest.raises(ParseError, match="DTD"):
        parse_events(text)


def test_missing_file_raises_parse_error(tmp_path):
    with pytest.raises(ParseError):
        load_events(tmp_path / "missing.xml")


def test_parse_time_handles_windows_precision_and_offsets():
    assert parse_time("2026-11-20T09:00:01.1234567Z") == datetime(
        2026, 11, 20, 9, 0, 1, 123456, tzinfo=timezone.utc
    )
    assert parse_time("2026-11-20T11:00:00+02:00") == datetime(2026, 11, 20, 9, 0, tzinfo=timezone.utc)
    with pytest.raises(ParseError):
        parse_time("yesterday")
