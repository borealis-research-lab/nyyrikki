# Validation

This file records results from running Nyyrikki against real Windows computers. It contains summary numbers only, never raw events or personal data.

To repeat the test on your own machine, run `scripts/real-test.ps1` (see the README). It is the same script that produced the results below.

## 2026-11-20: Windows 11 Home (build 26200), real-world test

- **Nyyrikki:** 0.1.0 (branch `feat/mvp-scan`)
- **Method:** `scripts/real-test.ps1 -IncludeBaseline`. A temporary local test account generated controlled events, only the test window was exported, and the script compared Nyyrikki's findings with what it expected.
- **Audit policy:** the Windows defaults were enough; nothing was changed.

| Check | Result |
|---|---|
| Real Security log export parsed | PASS (30 events in the test window) |
| `account-created` for the test account | PASS |
| `privileged-group-add` for the test account | PASS |
| `failed-logon-burst` (12 failures) | PASS |
| `failed-then-success` | PASS |
| No finding for 3 failures below the threshold | PASS |
| Every cited record ID exists in the live Security log | PASS (15 checked) |
| Unrelated findings in the test window | 0 |
| Baseline: previous 24 hours of normal activity | 14,159 events scanned in 1.45 s, 0 findings |

### What this does and doesn't show

- **Shown:** the parser handles real `wevtutil` exports. Four of the five rules fire on genuine Windows events produced by the corresponding actions. A below-threshold case stays quiet. Evidence references point to real records. Performance is practical (about 10,000 events per second).
- **Not shown:**
  - `audit-log-cleared` against real data. It was deliberately not run, because clearing the log destroys history; it is tested only with simulated events.
  - False-positive rates on busier, shared, server or domain-joined machines. One quiet home PC over 24 hours is limited evidence.
  - Detection of real attacks or attack tools. The events were controlled imitations.
  - The optional `--explain` with a real local model.
