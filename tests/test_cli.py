import json
from pathlib import Path

import pytest

from nyyrikki.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
ATTACK = str(FIXTURES / "simulated_attack.xml")
BENIGN = str(FIXTURES / "benign.xml")
ALL_RULES = {
    "failed-logon-burst",
    "failed-then-success",
    "account-created",
    "privileged-group-add",
    "audit-log-cleared",
}


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# JSON mode (borealis-agent-report/1; full conformance is in test_agent_report.py)


def test_json_report_contains_all_rules(capsys):
    code, out, err = run(capsys, "scan", ATTACK, "--json")
    report = json.loads(out)
    assert code == 0 and err == ""
    assert report["standard"] == "borealis-agent-report/1"
    assert report["agent"] == {"name": "nyyrikki", "version": "0.2.0"}
    assert report["findings_total"] == 5 and report["status"] == "ok"
    assert {f["rule_id"] for f in report["findings"]} == ALL_RULES
    assert "extensions" not in report  # no AI output unless --explain is used


def test_json_evidence_points_at_records_in_the_file(capsys):
    text = Path(ATTACK).read_text()
    _, out, _ = run(capsys, "scan", ATTACK, "--json")
    for f in json.loads(out)["findings"]:
        for item in f["evidence"]:
            assert f"<EventRecordID>{item['details']['record_id']}</EventRecordID>" in text


def test_json_benign_has_no_findings(capsys):
    _, out, _ = run(capsys, "scan", BENIGN, "--json")
    report = json.loads(out)
    assert report["findings"] == [] and report["findings_total"] == 0


def test_json_is_the_default_output(capsys):
    _, default_out, _ = run(capsys, "scan", ATTACK)
    _, json_out, _ = run(capsys, "scan", ATTACK, "--json")
    default, explicit = json.loads(default_out), json.loads(json_out)
    assert default["standard"] == "borealis-agent-report/1"
    for report in (default, explicit):  # identical apart from per-run id and timestamps
        report.pop("run")
        for finding in report["findings"]:
            finding.pop("created_at")
    assert default == explicit


def test_out_with_default_output_prints_json_once(capsys, tmp_path):
    target = tmp_path / "report.json"
    code, out, _ = run(capsys, "scan", ATTACK, "--out", str(target))
    assert code == 0 and json.loads(out)["findings_total"] == 5  # stdout is exactly one JSON report


def test_text_and_json_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", ATTACK, "--text", "--json"])
    assert exc.value.code == 2


# Text mode (--text)


def test_text_summary_lists_findings_by_severity(capsys):
    code, out, _ = run(capsys, "scan", ATTACK, "--text")
    assert code == 0
    assert out.startswith("Nyyrikki Security Report")
    assert "Events analysed: 17" in out and "High:   3" in out and "Medium: 2" in out
    assert out.index("Finding 1: High") < out.index("Medium (")
    assert "record IDs: 2001-2013" in out
    assert "Account:\n  administrator" in out
    assert "not a probability" in out
    assert "<Event" not in out  # no raw event content


def test_text_zero_findings_is_explicit_and_not_reassuring(capsys):
    _, out, _ = run(capsys, "scan", BENIGN, "--text")
    assert "Findings:        0" in out and "does not mean the system is safe" in out


def test_text_handles_missing_fields(capsys, tmp_path):
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4720</EventID>'
        '<TimeCreated SystemTime="2026-11-20T09:00:00Z"/><EventRecordID>5</EventRecordID>'
        "</System></Event>"
    )
    path = tmp_path / "sparse.xml"
    path.write_text(xml)
    code, out, _ = run(capsys, "scan", str(path), "--text")
    assert code == 0 and "Finding 1: Medium" in out and "Account:" not in out


# Save report mode


def test_out_saves_valid_json_and_still_prints_summary(capsys, tmp_path):
    target = tmp_path / "reports" / "report.json"  # parent created
    code, out, err = run(capsys, "scan", ATTACK, "--text", "--out", str(target))
    assert code == 0
    assert out.startswith("Nyyrikki Security Report")
    assert "report saved" in err
    assert json.loads(target.read_text())["findings_total"] == 5


def test_out_refuses_to_overwrite(capsys, tmp_path):
    target = tmp_path / "report.json"
    target.write_text("keep me")
    code, out, err = run(capsys, "scan", ATTACK, "--out", str(target))
    assert code == 2 and out == "" and "refusing to overwrite" in err
    assert target.read_text() == "keep me"


def test_out_reports_unwritable_destination(capsys, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    code, _, err = run(capsys, "scan", ATTACK, "--out", str(blocker / "report.json"))
    assert code == 2 and "cannot write report" in err


# Errors


def test_unreadable_input_exits_with_code_2(capsys, tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<Event><broken>")
    code, out, err = run(capsys, "scan", str(bad))
    assert code == 2 and out == "" and "invalid XML" in err


def test_explain_requires_model(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", BENIGN, "--explain"])
    assert exc.value.code == 2


def test_explain_refuses_non_local_model_url(capsys):
    code, _, err = run(
        capsys, "scan", BENIGN, "--explain", "--model", "m", "--ollama-url", "https://api.example.com"
    )
    assert code == 2 and "non-local" in err
