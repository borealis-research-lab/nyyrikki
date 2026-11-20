# Detections

Nyyrikki's detections are fixed rules. Each finding cites the events it is based on by `EventRecordID`.

`severity` is a label assigned by the rule (low, medium or high). It is **not** a probability, and it has not been calibrated against real-world data.

All thresholds are constants in `src/nyyrikki/rules.py`. They have been tested only against simulated events, not against real attacks.

| rule_id | Events | Logic | Severity |
|---|---|---|---|
| `failed-logon-burst` | 4625 | At least 10 failed logons for the same user name within 5 minutes | medium |
| `failed-then-success` | 4625, 4624 | A failed-logon burst followed by a successful logon for the same user name within 10 minutes | high |
| `account-created` | 4720 | A user account was created | medium |
| `privileged-group-add` | 4728, 4732, 4756 | A member was added to Administrators (`S-1-5-32-544`), Domain Admins (`-512`), Schema Admins (`-518`), Enterprise Admins (`-519`), or a group with one of those English names | high |
| `audit-log-cleared` | 1102 | The Security log was cleared (provider `Microsoft-Windows-Eventlog`) | high |

## Known limitations

- **Auditing must be enabled.** Windows doesn't record failed logons (4625) or account management events (4720, 4728, 4732, 4756) unless the matching audit policy is turned on. If those events are missing, the rules simply find nothing.
- **Accounts are matched by user name only.** The same name in different domains is treated as one account.
- **Expected false positives:**
  - Mistyped or cached passwords and misconfigured services produce bursts of failed logons.
  - A user who gets the password right after many tries matches `failed-then-success`.
  - Legitimate administrators create accounts, change group memberships and clear logs.
- **Expected false negatives:**
  - Slow password guessing that stays below the threshold.
  - Guessing spread across many accounts (password spraying).
  - Privileged groups not on the fixed list.
  - Any activity that isn't in the exported events.
- **When rules overlap:** one burst followed by a success produces both a `failed-logon-burst` and a `failed-then-success` finding.
- **Input is an export, not a live feed.** Nyyrikki only sees the events contained in the file it is given.

## Optional local explanation

With `--explain`, each finding is sent to a model running in a local OpenAI-compatible server, such as llama.cpp's `llama-server` at `http://127.0.0.1:8080`. Only `localhost` URLs are accepted (`--model-url`).

The model receives the rules as a system message and only that finding's evidence, labelled as untrusted data, as a separate user message. It must cite records as `[record:<id>]`. The explanation is rejected, and recorded under `interpretation_rejected`, if any of these apply:
- it is empty or too long;
- it cites no records;
- it cites a record that isn't in the evidence;
- it mentions an IP address that isn't in the evidence.

An accepted explanation appears under `interpretation`, separate from the evidence. Nyyrikki never acts on model output.

Citation checking catches some kinds of invention by the model, but not all. A cited explanation can still misread the evidence.
