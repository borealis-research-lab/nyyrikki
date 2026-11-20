# Nyyrikki setup prompt for Claude Code

Copy everything below the line into Claude Code, started in the folder where you keep projects (for example your user folder). Claude will install Nyyrikki, check that it works, and guide you through a real test on your own Windows computer.

You don't need programming or security experience. Claude explains each step and asks before doing anything that changes your computer.

---

You are helping me install and test **Nyyrikki**, an experimental open-source tool from Borealis Research that looks for potentially suspicious activity in Windows Security event logs. Repository: https://github.com/borealis-research-lab/nyyrikki

I am not necessarily a developer. Explain each step in plain language, keep explanations short, and ask me before any step that installs software or changes my computer.

## Privacy rules (these override everything else)

My Windows security logs contain personal information: user names, computer names, IP addresses and activity history. Nyyrikki is designed so this data stays on my computer. You, Claude, run partly in the cloud, so anything you read is sent off this computer. Therefore:

1. **Never open, read, print, search, summarise or upload any file in the `exports` folder**, or any other exported Security log, event XML or Nyyrikki report made from my real data. The only exception is `results.txt`, which is designed to contain no personal data.
2. **Never run commands that print real security events or real Nyyrikki findings into this conversation.** That includes `wevtutil`, `Get-WinEvent`, `nyyrikki scan` on real exports, and reading `*-report.json`. I will run those myself, in my own window.
3. The test files in `tests/fixtures` are simulated data. You may read and scan those.
4. If I paste real log content or real findings into the chat, remind me that it leaves my computer, and work with the minimum needed.
5. Never send my data to any website or API, never push to GitHub or post anything on my behalf, and never change security settings yourself.

## Steps

1. **Check the computer.** Confirm this is Windows 10 or 11. Check whether Git and Python 3.10 or newer are installed (`git --version`, `py --version` or `python --version`). If either is missing, explain what it is and offer to install it with `winget` after I agree. Nyyrikki currently supports Windows only. If I'm on another system, stop and tell me.
2. **Get Nyyrikki.** Clone the repository into a `nyyrikki` folder, unless that folder already exists. If it does, ask me what to do and don't overwrite it.
3. **Install it.** In the `nyyrikki` folder, create a virtual environment and install the package with its test tools. On Windows: `py -m venv .venv`, then `.venv\Scripts\python -m pip install -e ".[dev]"`. Explain that this installs it only inside the project folder.
4. **Run the automated tests:** `.venv\Scripts\python -m pytest`. Tell me how many passed. If any failed, show me the failure and stop.
5. **Demonstrate it on simulated data:** `.venv\Scripts\nyyrikki scan tests\fixtures\simulated_attack.xml`. Walk me through one finding: what happened, why it matters, and how the record IDs point to the evidence. Then run it on `tests\fixtures\benign.xml` and point out that normal activity gives no findings.
6. **Pre-check the real test (read-only):** `powershell -ExecutionPolicy Bypass -File scripts\real-test.ps1 -CheckOnly`. Explain anything that failed.
7. **Explain the real test before I run it.** Summarise what `scripts\real-test.ps1` will do. Read the script and describe it honestly:
   - It creates a temporary test account that expires after an hour, and adds it to Administrators for a moment.
   - It makes some deliberately failed logons and one successful logon, then deletes the account.
   - It may ask to temporarily enable Windows audit logging, and restores the previous setting afterwards.
   - It exports only the test-window events to the `exports` folder.
   - It never clears logs or sends anything anywhere.

   Tell me that it has to run in an **administrator** PowerShell, which **I open and run myself**, not you, because its output contains my real data. Give me the exact commands:
   ```
   cd <full path to the nyyrikki folder>
   powershell -ExecutionPolicy Bypass -File scripts\real-test.ps1
   ```
   Add `-IncludeBaseline` if I also want to check the last 24 hours of my normal activity for false positives.
8. **Read the result.** When I say it has finished, read only `exports\real-test-<time>\results.txt` (the newest one) and explain each PASS, FAIL or SKIP line in plain language. If something failed, suggest likely causes, for example audit settings managed by an organisation or a security product blocking the test. Do not open the other files in that folder to investigate; ask me questions instead.
9. **Finish.** Remind me that the `exports` folder contains my personal security data, which I can delete when I no longer need it. Tell me that bugs can be reported at https://github.com/borealis-research-lab/nyyrikki/issues, **without** attaching real logs or reports, and that vulnerabilities go privately through the repository's Security tab.

Nyyrikki is experimental and is not a production security product. Don't tell me my computer is safe or compromised based on these results.
