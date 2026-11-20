# Contributing to Nyyrikki

Nyyrikki has a deliberately narrow purpose: identify potentially suspicious activity in one local source of security events, with findings grounded in the source evidence. See [docs/scope.md](docs/scope.md).

Please open an issue to discuss substantial or scope-changing proposals before submitting them.

## Development

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
```

No formatter or linter is configured yet.

## Guidelines

- Behaviour changes require tests.
- Update documentation where relevant.
- Technical identifiers (project, package, path, variable, configuration key and branch names) must be ASCII-only.
- Do not submit secrets, credentials, personal security logs or model weights.
