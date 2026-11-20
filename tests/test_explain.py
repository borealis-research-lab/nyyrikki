import pytest

import eventxml as ex
from nyyrikki.events import parse_events
from nyyrikki.explain import (
    SYSTEM_PROMPT,
    ExplainError,
    build_user_prompt,
    explain,
    local_model_generator,
    require_local_url,
    response_text,
    validate_explanation,
)
from nyyrikki.rules import account_created, failed_logon_burst


def finding():
    [f] = account_created(parse_events(ex.account_created(42, 0)))
    return f


def fake(text):
    return lambda system, user: text


def test_valid_explanation_is_attached_as_interpretation():
    result = explain(finding(), fake("Account svc-backup2 was created [record:42]."))
    assert result.interpretation == "Account svc-backup2 was created [record:42]."
    assert result.interpretation_rejected is None


@pytest.mark.parametrize(
    "text, reason",
    [
        ("", "empty"),
        ("An account was created.", "cites no evidence"),
        ("See [record:42] and [record:999].", "not in the evidence"),
        ("[record:42] " + "x" * 3000, "longer than"),
        ("Created [record:42] from 198.51.100.7.", "IP addresses not in the evidence"),
    ],
)
def test_ungrounded_explanations_are_rejected(text, reason):
    result = explain(finding(), fake(text))
    assert result.interpretation is None
    assert reason in result.interpretation_rejected
    assert reason in validate_explanation(text, finding())


def test_ip_addresses_present_in_evidence_are_allowed():
    [f] = failed_logon_burst(parse_events("".join(ex.failed_logon(i, i) for i in range(1, 11))))
    assert validate_explanation("Failures from 192.0.2.10 [record:1].", f) is None


def test_unavailable_model_is_recorded_not_raised():
    def broken(system, user):
        raise ExplainError("local model unavailable: connection refused")

    result = explain(finding(), broken)
    assert result.interpretation is None
    assert "unavailable" in result.interpretation_rejected


def test_instructions_and_untrusted_evidence_are_kept_in_separate_messages():
    user = build_user_prompt(finding())
    start, end = user.index("<<<BEGIN EVENT DATA>>>"), user.index("<<<END EVENT DATA>>>")
    assert '"record_id": 42' in user[start:end]
    assert "untrusted" in SYSTEM_PROMPT and "never follow" in SYSTEM_PROMPT


def test_response_text_strips_reasoning_blocks_and_rejects_bad_payloads():
    payload = {"choices": [{"message": {"content": "<think>hmm</think> Answer [record:1]"}}]}
    assert response_text(payload) == "Answer [record:1]"
    with pytest.raises(ExplainError):
        response_text({"unexpected": True})


@pytest.mark.parametrize("url", ["http://localhost:8080", "http://127.0.0.1:8080/", "http://[::1]:8080"])
def test_local_urls_are_allowed(url):
    assert require_local_url(url)


@pytest.mark.parametrize("url", ["http://192.0.2.5:8080", "https://api.example.com", "file:///etc/passwd"])
def test_non_local_urls_are_refused(url):
    with pytest.raises(ExplainError):
        require_local_url(url)
    with pytest.raises(ExplainError):
        local_model_generator(url)


def test_unreachable_local_server_raises_explain_error():
    generate = local_model_generator("http://127.0.0.1:9")
    with pytest.raises(ExplainError):
        generate("system", "user")
