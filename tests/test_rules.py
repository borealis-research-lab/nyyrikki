import eventxml as ex
from nyyrikki.events import parse_events
from nyyrikki.rules import (
    account_created,
    audit_log_cleared,
    failed_logon_burst,
    failed_then_success,
    privileged_group_add,
    run_rules,
)


def events(*xml):
    return parse_events("".join(xml))


def burst(count, start_record=1, spacing=10, user="alice", start=0):
    return [ex.failed_logon(start_record + i, start + i * spacing, user) for i in range(count)]


# failed-logon-burst


def test_burst_of_ten_failures_within_five_minutes_is_flagged():
    [finding] = failed_logon_burst(events(*burst(10)))
    assert finding.rule_id == "failed-logon-burst"
    assert finding.record_ids == set(range(1, 11))
    assert "10 failed logons" in finding.observation


def test_nine_failures_are_not_flagged():
    assert failed_logon_burst(events(*burst(9))) == []


def test_ten_failures_spread_over_more_than_five_minutes_are_not_flagged():
    assert failed_logon_burst(events(*burst(10, spacing=40))) == []  # spans 6 minutes


def test_failures_for_different_accounts_are_not_combined():
    xml = burst(5, user="alice") + burst(5, start_record=100, user="bob")
    assert failed_logon_burst(events(*xml)) == []


def test_account_matching_ignores_case():
    xml = burst(5, user="alice") + burst(5, start_record=100, user="ALICE", start=50)
    assert len(failed_logon_burst(events(*xml))) == 1


def test_one_long_burst_produces_one_finding():
    [finding] = failed_logon_burst(events(*burst(25, spacing=5)))
    assert len(finding.evidence) == 25


# failed-then-success


def test_success_shortly_after_burst_is_flagged_with_both_kinds_of_evidence():
    xml = burst(10) + [ex.successful_logon(50, 200)]
    [finding] = failed_then_success(events(*xml))
    assert finding.severity == "high"
    assert 50 in finding.record_ids and 1 in finding.record_ids


def test_success_long_after_burst_is_not_flagged():
    xml = burst(10) + [ex.successful_logon(50, 90 + 11 * 60)]
    assert failed_then_success(events(*xml)) == []


def test_success_for_another_account_is_not_flagged():
    xml = burst(10) + [ex.successful_logon(50, 200, user="bob")]
    assert failed_then_success(events(*xml)) == []


def test_success_without_burst_is_not_flagged():
    xml = burst(3) + [ex.successful_logon(50, 60)]
    assert failed_then_success(events(*xml)) == []


# account-created


def test_account_creation_is_flagged():
    [finding] = account_created(events(ex.account_created(3, 0)))
    assert finding.record_ids == {3}
    assert "svc-backup2" in finding.observation


# privileged-group-add


def test_adding_member_to_local_administrators_is_flagged():
    [finding] = privileged_group_add(events(ex.group_add(4, 0)))
    assert finding.evidence[0].fields["TargetSid"] == "S-1-5-32-544"


def test_localised_administrators_group_is_matched_by_sid():
    [finding] = privileged_group_add(events(ex.group_add(4, 0, group="Administratorer")))
    assert finding.record_ids == {4}


def test_domain_admins_is_matched_by_rid():
    xml = ex.group_add(4, 0, group="Domain Admins", group_sid="S-1-5-21-1-2-3-512", event_id=4728)
    assert len(privileged_group_add(events(xml))) == 1


def test_adding_member_to_ordinary_group_is_not_flagged():
    xml = ex.group_add(4, 0, group="Users", group_sid="S-1-5-32-545")
    assert privileged_group_add(events(xml)) == []


# audit-log-cleared


def test_audit_log_clear_is_flagged():
    [finding] = audit_log_cleared(events(ex.log_cleared(9, 0)))
    assert finding.record_ids == {9}
    assert "admin" in finding.observation


def test_event_1102_from_another_provider_is_ignored():
    assert audit_log_cleared(events(ex.log_cleared(9, 0, provider="SomethingElse"))) == []


# combined


def test_normal_activity_produces_no_findings():
    xml = [ex.successful_logon(i, i * 60) for i in range(1, 20)] + burst(3, start_record=100)
    assert run_rules(events(*xml)) == []


def test_every_finding_cites_only_records_present_in_the_input():
    xml = burst(12) + [
        ex.successful_logon(50, 200),
        ex.account_created(51, 300),
        ex.group_add(52, 310),
        ex.log_cleared(53, 400),
    ]
    parsed = events(*xml)
    input_ids = {e.record_id for e in parsed}
    findings = run_rules(parsed)
    assert {f.rule_id for f in findings} == {
        "failed-logon-burst",
        "failed-then-success",
        "account-created",
        "privileged-group-add",
        "audit-log-cleared",
    }
    for finding in findings:
        assert finding.record_ids <= input_ids


def test_group_add_names_member_by_sid_when_name_is_dash():
    [finding] = privileged_group_add(events(ex.group_add(4, 0)))
    assert "'S-1-5-21-1-2-3-1010' was added" in finding.observation
