# Nyyrikki

Nyyrikki is a small local AI security scout that identifies potentially suspicious activity in local security events.

It is a project of [Borealis Research](https://github.com/borealis-research-lab), an independent open-source research laboratory exploring distributed computing, specialised AI agents and resilient digital infrastructure.

> **Experimental.** Nyyrikki is not a production security product. Do not rely on it to protect any system.

## Status

Early MVP. Nyyrikki scans Windows Security events exported to XML and applies five fixed detection rules (see [docs/detections.md](docs/detections.md)). The rules have been tested against simulated events only; they are not calibrated against real attacks.

Not yet supported: reading the live event log, continuous monitoring, other operating systems. No local model has been selected; Ollama is supported as an optional runtime.

## Usage

Export events (reading the Security log needs an administrator terminal), then scan the export:

```powershell
mkdir exports
wevtutil qe Security /f:xml /rd:true /c:5000 > exports\security.xml
nyyrikki scan exports\security.xml
```

To scan an `.evtx` file exported elsewhere, convert it first with `wevtutil qe file.evtx /lf:true /f:xml > exports\file.xml`.

By default Nyyrikki prints a short human-readable report. Each finding has: what happened, when, the account involved, why it matters, a recommended action, and the record IDs of the supporting events so they can be checked in Event Viewer. Nyyrikki never changes the system.

| Option | Effect |
|---|---|
| `--json` | Print the JSON report instead of the summary |
| `--out report.json` | Also save the JSON report to a local file. Never overwrites an existing file |

`nyyrikki describe` prints the agent's identity (name, version, responsibility, and the kinds of personal data its reports can contain).

The JSON report follows the [Borealis agent report standard](https://github.com/borealis-research-lab/.github/tree/main/standards) (`borealis-agent-report/1`), so other Borealis tools such as Borealis Node can validate and combine it:
- each finding has a deterministic `finding_id`;
- evidence references take the form `windows-security:record:<EventRecordID>`, with the event's fields under `details`;
- `status`, `errors` and the totals say if anything was truncated.

The report never contains the export's file name or path. It does contain account names, IP addresses and computer names from the events, so review it before sharing.

**Data warnings:** if an event field contains text that looks like instructions (for example to an AI tool), Nyyrikki adds a data warning to the finding. A warning is an indicator for a human to review, not a detection.

Try it with simulated data: `nyyrikki scan tests/fixtures/simulated_attack.xml`.

## Testing on your own computer

`scripts/real-test.ps1` runs a controlled, harmless test on a real Windows computer. It uses a temporary test account to generate the events each rule looks for, then checks that Nyyrikki finds them. See the comment at the top of the script for exactly what it does. Start with `-CheckOnly`, which makes no changes.

Using Claude Code? Paste [SETUP_PROMPT.md](SETUP_PROMPT.md) into it for guided installation and testing. The prompt tells Claude never to read your real security logs, because anything Claude reads leaves your computer.

Optional explanation by a local model running in [Ollama](https://ollama.com):

```bash
nyyrikki scan exports/security.xml --explain --model <local-model-name>
```

Only localhost model URLs are accepted. Explanations that do not cite the finding's evidence, or cite events outside it, are rejected.

Real event exports and reports contain personal data (user names, computer names, IP addresses). `exports/` is git-ignored; do not commit or share them, and do not paste them into cloud AI tools.

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
