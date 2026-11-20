import json
from pathlib import Path

import pytest

from nyyrikki.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_scan_simulated_attack_reports_all_rules(capsys):
    code, out, _ = run(capsys, "scan", str(FIXTURES / "simulated_attack.xml"))
    report = json.loads(out)
    assert code == 0
    assert report["agent"] == "nyyrikki"
    assert report["events_parsed"] > 0
    assert {f["rule_id"] for f in report["findings"]} == {
        "failed-logon-burst",
        "failed-then-success",
        "account-created",
        "privileged-group-add",
        "audit-log-cleared",
    }
    for f in report["findings"]:
        assert f["agent"] == "nyyrikki"
        assert f["evidence"] and f["observation"] and f["recommendation"]
        assert f["interpretation"] is None


def test_scan_benign_activity_reports_no_findings(capsys):
    code, out, _ = run(capsys, "scan", str(FIXTURES / "benign.xml"))
    assert code == 0
    assert json.loads(out)["findings"] == []


def test_fixture_evidence_points_at_records_in_the_file(capsys):
    text = (FIXTURES / "simulated_attack.xml").read_text()
    _, out, _ = run(capsys, "scan", str(FIXTURES / "simulated_attack.xml"))
    for f in json.loads(out)["findings"]:
        for item in f["evidence"]:
            assert f"<EventRecordID>{item['record_id']}</EventRecordID>" in text


def test_unreadable_input_exits_with_code_2(capsys, tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<Event><broken>")
    code, out, err = run(capsys, "scan", str(bad))
    assert code == 2 and out == "" and "invalid XML" in err


def test_explain_requires_model(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(FIXTURES / "benign.xml"), "--explain"])
    assert exc.value.code == 2


def test_explain_refuses_non_local_model_url(capsys):
    code, _, err = run(
        capsys, "scan", str(FIXTURES / "benign.xml"), "--explain", "--model", "m",
        "--ollama-url", "https://api.example.com",
    )
    assert code == 2 and "non-local" in err
