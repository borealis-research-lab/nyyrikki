# Vendored copies (test-only)

These files are **copied unchanged** from the Borealis reporting standards, so Nyyrikki's
tests can check conformance without any runtime dependency:

- Source: https://github.com/borealis-research-lab/.github/tree/main/standards
- Commit: `17601f2` (merge of PR #1, standards v1)
- Files: `agent-report-v1.schema.json`, `test-vectors-v1.json`, `tools/check_report.py`

Do not edit them here. If the standard changes, copy the new versions and update this note.
Nyyrikki's own implementation of the standard is `src/nyyrikki/standard.py`.
