import pytest

import eventxml as ex
from nyyrikki.events import parse_events
from nyyrikki.explain import (
    ExplainError,
    build_prompt,
    explain,
    ollama_generator,
    require_local_url,
    validate_explanation,
)
from nyyrikki.rules import account_created


def finding():
    [f] = account_created(parse_events(ex.account_created(42, 0)))
    return f


def test_valid_explanation_is_attached_as_interpretation():
    result = explain(finding(), lambda prompt: "Account svc-backup2 was created [record:42].")
    assert result.interpretation == "Account svc-backup2 was created [record:42]."
    assert result.interpretation_rejected is None


@pytest.mark.parametrize(
    "text, reason",
    [
        ("", "empty"),
        ("An account was created.", "cites no evidence"),
        ("See [record:42] and [record:999].", "not in the evidence"),
        ("[record:42] " + "x" * 3000, "longer than"),
    ],
)
def test_ungrounded_explanations_are_rejected(text, reason):
    result = explain(finding(), lambda prompt: text)
    assert result.interpretation is None
    assert reason in result.interpretation_rejected
    assert reason in validate_explanation(text, finding())


def test_unavailable_model_is_recorded_not_raised():
    def broken(prompt):
        raise ExplainError("local model unavailable: connection refused")

    result = explain(finding(), broken)
    assert result.interpretation is None
    assert "unavailable" in result.interpretation_rejected


def test_prompt_contains_evidence_inside_untrusted_data_block():
    prompt = build_prompt(finding())
    start, end = prompt.index("<<<BEGIN EVENT DATA>>>"), prompt.index("<<<END EVENT DATA>>>")
    assert '"record_id": 42' in prompt[start:end]
    assert "untrusted" in prompt.lower()


@pytest.mark.parametrize("url", ["http://localhost:11434", "http://127.0.0.1:11434/", "http://[::1]:11434"])
def test_local_urls_are_allowed(url):
    assert require_local_url(url)


@pytest.mark.parametrize("url", ["http://192.0.2.5:11434", "https://api.example.com", "file:///etc/passwd"])
def test_non_local_urls_are_refused(url):
    with pytest.raises(ExplainError):
        require_local_url(url)
    with pytest.raises(ExplainError):
        ollama_generator("some-model", url)


def test_unreachable_local_ollama_raises_explain_error():
    generate = ollama_generator("some-model", "http://127.0.0.1:9", timeout=2)
    with pytest.raises(ExplainError):
        generate("hello")
