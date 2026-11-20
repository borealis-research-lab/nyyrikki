# Nyyrikki

Nyyrikki is a small local AI security scout that identifies potentially suspicious activity in local security events.

It is a project of [Borealis Research](https://github.com/borealis-research), an independent open-source research laboratory exploring distributed computing, specialised AI agents and resilient digital infrastructure.

> **Experimental.** Nyyrikki is not a production security product. Do not rely on it to protect any system.

## Status

Repository bootstrap. The security agent itself is not yet implemented, and no detection functionality exists.

The first supported operating system, event source, local model and model runtime have not yet been selected.

## Single responsibility

Monitor a narrowly selected source of local security events and identify activity that may be suspicious, returning a concise assessment grounded in the original event evidence.

A small, locally running open-weight language model may be used to help interpret event context. The model is an assistant for interpreting evidence, not a source of truth: findings must point back to the actual source events, and the model must not invent events, indicators, timestamps or process names.

## Scope and non-goals

In scope: one local event source, identification of potentially suspicious activity, and structured findings tied to source events, all running locally.

Out of scope: distributed computing, multi-agent orchestration, threat-intelligence or vulnerability feeds, network or vulnerability scanning, offensive security, automatic remediation or blocking, dashboards or hosted services, cloud LLM APIs, and heavy infrastructure. See [docs/scope.md](docs/scope.md) for the full list.

## Development setup

Requires Python 3.10 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
