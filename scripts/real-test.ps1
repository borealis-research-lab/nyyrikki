<#
.SYNOPSIS
    Repeatable real-world test of Nyyrikki against this computer's Windows Security events.

.DESCRIPTION
    Generates a small, harmless, controlled set of security events using a temporary
    local test account, exports only those events, scans them with Nyyrikki and checks
    that the expected findings appear (and that a below-threshold case does not).

    What it does (only after you confirm):
      - Creates a temporary local account 'nyyrikki-test' with a random password nobody
        sees. The account is set to expire after 1 hour as a safety net.
      - Temporarily adds it to the local Administrators group.
      - Performs 3 failed logons for a non-existent account 'nyyrikki-nouser' (below threshold).
      - Performs 12 failed logons and then 1 successful logon for 'nyyrikki-test'
        (local authentication only; no network traffic leaves this computer).
      - Removes the account from Administrators and deletes it.
      - Exports the Security events from the test window to exports\real-test-<time>\.

    What it never does: clear or delete event logs, disable security features, change
    existing accounts, send data anywhere, or print raw events to the terminal.

    If required audit settings are off, it explains and asks before enabling them, and
    restores the previous audit policy afterwards.

.PARAMETER CheckOnly
    Only run the read-only checks. Makes no changes. Does not need administrator rights.

.PARAMETER IncludeBaseline
    Also export and scan the 24 hours of normal activity before the test, to count
    false positives. This exports more of your real data (still kept local).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\real-test.ps1 -CheckOnly
    powershell -ExecutionPolicy Bypass -File scripts\real-test.ps1 -IncludeBaseline
#>
[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$IncludeBaseline
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TestUser = 'nyyrikki-test'
$GhostUser = 'nyyrikki-nouser'
$BurstCount = 12
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Nyyrikki = Join-Path $RepoRoot '.venv\Scripts\nyyrikki.exe'
$AdministratorsSid = 'S-1-5-32-544'

# Audit subcategories (GUIDs are language-independent).
$AuditNeeds = @(
    @{ Name = 'Logon';                     Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Failure = $true },
    @{ Name = 'User Account Management';   Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Failure = $false },
    @{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Failure = $false }
)

function Write-Section([string]$Text) { Write-Host ''; Write-Host "== $Text ==" -ForegroundColor Cyan }
function Write-Ok([string]$Text) { Write-Host "  [ok]   $Text" -ForegroundColor Green }
function Write-Bad([string]$Text) { Write-Host "  [fail] $Text" -ForegroundColor Red }
function Write-Note([string]$Text) { Write-Host "  $Text" }

function Confirm-Step([string]$Question) {
    $answer = Read-Host "$Question [y/N]"
    return ($answer -eq 'y' -or $answer -eq 'Y')
}

function Test-IsAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-RandomSecret {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=?'
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return 'Aa1!' + (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] }))
}

function Get-AuditSetting([string]$Guid) {
    # CSV columns: Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting, ...
    $lines = & auditpol.exe /get "/subcategory:$Guid" /r
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $Guid" }
    $row = $lines | Where-Object { $_ -match [regex]::Escape($Guid) } | Select-Object -First 1
    if (-not $row) { return '' }
    return ($row -split ',')[4]
}

function Test-AuditSufficient([string]$Setting, [bool]$NeedFailure) {
    # English values: 'Success', 'Failure', 'Success and Failure', 'No Auditing'.
    if ($NeedFailure) { return ($Setting -match 'Success' -and $Setting -match 'Failure') }
    return ($Setting -match 'Success')
}

function Export-SecurityEvents([string]$Query, [string]$Path) {
    & wevtutil.exe qe Security "/q:$Query" /f:xml | Out-File -FilePath $Path -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw "wevtutil export failed (exit $LASTEXITCODE)" }
}

function Format-XPathTime([datetime]$Utc) { return $Utc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }

# ---------------------------------------------------------------------------
Write-Host 'Nyyrikki real-world test' -ForegroundColor Cyan
Write-Host 'This script generates a few harmless security events with a temporary test account,'
Write-Host 'exports only those events, and checks that Nyyrikki finds what it should.'
Write-Host 'Raw exports stay on this computer under exports\ (git-ignored). Nothing is uploaded.'

# --- 1. Read-only checks ----------------------------------------------------
Write-Section '1. Checks (read-only)'
$checksOk = $true

$os = Get-CimInstance Win32_OperatingSystem
Write-Ok "Operating system: $($os.Caption) build $($os.BuildNumber)"
if ($PSVersionTable.PSVersion.Major -lt 5) { Write-Bad "PowerShell 5.1 or newer required"; $checksOk = $false }
else { Write-Ok "PowerShell $($PSVersionTable.PSVersion)" }

if (Test-Path $Nyyrikki) {
    $version = & $Nyyrikki --version
    Write-Ok "Nyyrikki found: $version"
} else {
    Write-Bad "Nyyrikki not found at $Nyyrikki. Install it first (see README: python -m pip install -e .)"
    $checksOk = $false
}

if (Get-Command New-LocalUser -ErrorAction SilentlyContinue) { Write-Ok 'LocalAccounts module available' }
else { Write-Bad 'New-LocalUser not available (Microsoft.PowerShell.LocalAccounts)'; $checksOk = $false }

$existing = Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
if ($existing) {
    Write-Bad "An account named '$TestUser' already exists (left over from an earlier run?)."
    Write-Note "Remove it in an administrator PowerShell with: Remove-LocalUser -Name $TestUser"
    $checksOk = $false
} else { Write-Ok "No existing '$TestUser' account" }

$isAdmin = Test-IsAdmin
if ($isAdmin) { Write-Ok 'Running as administrator' }
else { Write-Note 'Not running as administrator. The test itself needs an administrator PowerShell.' }

$auditMissing = @()
if ($isAdmin) {
    foreach ($need in $AuditNeeds) {
        $setting = Get-AuditSetting $need.Guid
        if (Test-AuditSufficient $setting $need.Failure) { Write-Ok "Audit '$($need.Name)': $setting" }
        else {
            $wanted = 'Success'; if ($need.Failure) { $wanted = 'Success and Failure' }
            Write-Bad "Audit '$($need.Name)': '$setting' (needs $wanted)"
            $auditMissing += $need
        }
    }
} else {
    Write-Note 'Audit policy can only be read as administrator; skipped.'
}

if ($CheckOnly) {
    Write-Section 'Check-only mode: no changes were made.'
    if ($checksOk) { exit 0 } else { exit 1 }
}
if (-not $checksOk) { Write-Host ''; Write-Host 'Fix the failed checks above and run again.'; exit 2 }
if (-not $isAdmin) {
    Write-Host ''
    Write-Host 'Please re-run this script from an administrator PowerShell:'
    Write-Host '  Start menu > type PowerShell > right-click > Run as administrator'
    exit 2
}

# --- 2. Audit policy (only if needed) ----------------------------------------
$auditBackup = $null
$outDir = Join-Path $RepoRoot ('exports\real-test-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))

if ($auditMissing.Count -gt 0) {
    Write-Section '2. Audit policy'
    Write-Host 'Windows is not recording some events this test needs. The script can TEMPORARILY enable:'
    foreach ($need in $auditMissing) {
        $flags = '/success:enable'; if ($need.Failure) { $flags += ' /failure:enable' }
        Write-Note "auditpol /set /subcategory:`"$($need.Name)`" $flags"
    }
    Write-Host 'This only adds logging; it does not weaken security. The current policy is backed up'
    Write-Host 'first and restored automatically at the end. If your audit policy is managed by Group'
    Write-Host 'Policy, it may be overwritten later anyway.'
    if (-not (Confirm-Step 'Enable these audit settings for the duration of the test?')) {
        Write-Host 'Stopped. Without these settings the test cannot produce the events it checks for.'
        exit 2
    }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $auditBackup = Join-Path $outDir 'auditpol-backup.csv'
    & auditpol.exe /backup "/file:$auditBackup" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol backup failed; nothing was changed.' }
    Write-Note "Previous audit policy saved to $auditBackup"
    Write-Note "Manual restore if needed: auditpol /restore /file:`"$auditBackup`""
    foreach ($need in $auditMissing) {
        if ($need.Failure) { & auditpol.exe /set "/subcategory:$($need.Guid)" /success:enable /failure:enable | Out-Null }
        else { & auditpol.exe /set "/subcategory:$($need.Guid)" /success:enable | Out-Null }
    }
}

# --- 3. Scenario ---------------------------------------------------------------
Write-Section '3. Test scenario'
Write-Host "The script will now:"
Write-Note "1. Create temporary local account '$TestUser' (random password, expires in 1 hour)"
Write-Note "2. Add it to the local Administrators group                 -> expect: privileged-group-add"
Write-Note "   (account creation itself                                 -> expect: account-created)"
Write-Note "3. 3 failed logons for non-existent '$GhostUser'        -> expect: NO finding"
Write-Note "4. $BurstCount failed logons for '$TestUser'                       -> expect: failed-logon-burst"
Write-Note "5. 1 successful logon for '$TestUser'                          -> expect: failed-then-success"
Write-Note "6. Remove it from Administrators and delete the account"
Write-Host 'The test account may be locked out by Windows after repeated failures; the script unlocks'
Write-Host 'only that test account. If the script is interrupted, remove the account with:'
Write-Note "Remove-LocalUser -Name $TestUser"
if (-not (Confirm-Step 'Run the test scenario now?')) {
    if ($auditBackup) { & auditpol.exe /restore "/file:$auditBackup" | Out-Null; Write-Note 'Audit policy restored.' }
    Write-Host 'Stopped. No account was created.'
    exit 2
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NyyrikkiTestLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    public static bool TryNetworkLogon(string user, string domain, string password) {
        IntPtr token;
        bool ok = LogonUser(user, domain, password, 3, 0, out token);
        if (ok) { CloseHandle(token); }
        return ok;
    }
}
'@

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$start = (Get-Date).ToUniversalTime()
Start-Sleep -Seconds 1
$secret = New-RandomSecret
$testSid = $null
$successOk = $false
$unlockNote = ''

try {
    $secure = ConvertTo-SecureString $secret -AsPlainText -Force
    $account = New-LocalUser -Name $TestUser -Password $secure -AccountExpires (Get-Date).AddHours(1) `
        -Description 'Temporary Nyyrikki test account (safe to delete)' -PasswordNeverExpires
    $testSid = $account.SID.Value
    Write-Ok "Created $TestUser"

    Add-LocalGroupMember -SID $AdministratorsSid -Member $TestUser
    Write-Ok 'Added to Administrators'

    for ($i = 0; $i -lt 3; $i++) { [void][NyyrikkiTestLogon]::TryNetworkLogon($GhostUser, $env:COMPUTERNAME, (New-RandomSecret)) }
    Write-Ok "3 failed logons for $GhostUser"

    for ($i = 0; $i -lt $BurstCount; $i++) {
        [void][NyyrikkiTestLogon]::TryNetworkLogon($TestUser, $env:COMPUTERNAME, (New-RandomSecret))
        Start-Sleep -Milliseconds 200
    }
    Write-Ok "$BurstCount failed logons for $TestUser"

    $wmiUser = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$TestUser'"
    if ($wmiUser -and $wmiUser.Lockout) {
        try {
            Set-CimInstance -InputObject $wmiUser -Property @{ Lockout = $false }
            $unlockNote = 'test account was locked out by Windows and was unlocked'
        } catch { $unlockNote = 'test account was locked out and could not be unlocked' }
        Write-Note $unlockNote
    }

    $successOk = [NyyrikkiTestLogon]::TryNetworkLogon($TestUser, $env:COMPUTERNAME, $secret)
    if ($successOk) { Write-Ok "Successful logon for $TestUser" } else { Write-Bad "Successful logon for $TestUser did not succeed" }
    Start-Sleep -Seconds 2
}
finally {
    $secret = $null
    if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
        try { Remove-LocalGroupMember -SID $AdministratorsSid -Member $TestUser -ErrorAction Stop; Write-Ok 'Removed from Administrators' }
        catch { Write-Note 'Group membership removal skipped (not a member)' }
        Remove-LocalUser -Name $TestUser
    }
    if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) { Write-Bad "Could not delete $TestUser - remove it manually: Remove-LocalUser -Name $TestUser" }
    else { Write-Ok "Deleted $TestUser" }
    if ($auditBackup) {
        & auditpol.exe /restore "/file:$auditBackup" | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Ok 'Audit policy restored to its previous state' }
        else { Write-Bad "Audit policy restore failed. Run: auditpol /restore /file:`"$auditBackup`"" }
    }
}

# --- 4. Export and scan ---------------------------------------------------------
Write-Section '4. Export and scan'
$end = (Get-Date).ToUniversalTime().AddSeconds(5)
$scenarioXml = Join-Path $outDir 'scenario-events.xml'
$scenarioReport = Join-Path $outDir 'scenario-report.json'
$windowQuery = "*[System[TimeCreated[@SystemTime>='$(Format-XPathTime $start)' and @SystemTime<='$(Format-XPathTime $end)']]]"
Export-SecurityEvents $windowQuery $scenarioXml
Write-Ok "Exported test-window events to $scenarioXml"

& $Nyyrikki scan $scenarioXml --out $scenarioReport
if ($LASTEXITCODE -ne 0) { Write-Bad 'Nyyrikki failed to scan the export'; exit 1 }
$report = Get-Content -Raw -Path $scenarioReport | ConvertFrom-Json

# --- 5. Check results ------------------------------------------------------------
Write-Section '5. Results'
$results = New-Object System.Collections.Generic.List[string]
$allPass = $true

function Add-Result([string]$Name, [bool]$Pass, [string]$Detail) {
    $status = 'FAIL'; if ($Pass) { $status = 'PASS' }
    $line = "{0}  {1}{2}" -f $status, $Name, $(if ($Detail) { " ($Detail)" } else { '' })
    $results.Add($line)
    if ($Pass) { Write-Ok "$Name $Detail" } else { Write-Bad "$Name $Detail"; $script:allPass = $false }
}

function Get-Findings([string]$RuleId) { @($report.findings | Where-Object { $_.rule_id -eq $RuleId }) }
function Test-EvidenceField($Finding, [string]$Field, [string]$Value) {
    foreach ($item in $Finding.evidence) {
        $prop = $item.fields.PSObject.Properties[$Field]
        if ($prop -and $prop.Value -ieq $Value) { return $true }
    }
    return $false
}

Add-Result 'export parsed' ($report.counts.events -gt 0) "$($report.counts.events) events"
Add-Result 'account-created for test account' (@(Get-Findings 'account-created' | Where-Object { Test-EvidenceField $_ 'TargetUserName' $TestUser }).Count -ge 1) ''
Add-Result 'privileged-group-add for test account' (@(Get-Findings 'privileged-group-add' | Where-Object { Test-EvidenceField $_ 'MemberSid' $testSid }).Count -ge 1) ''
Add-Result 'failed-logon-burst for test account' (@(Get-Findings 'failed-logon-burst' | Where-Object { Test-EvidenceField $_ 'TargetUserName' $TestUser }).Count -ge 1) ''
if ($successOk) {
    Add-Result 'failed-then-success for test account' (@(Get-Findings 'failed-then-success' | Where-Object { Test-EvidenceField $_ 'TargetUserName' $TestUser }).Count -ge 1) ''
} else {
    $results.Add("SKIP  failed-then-success (successful logon could not be performed: $unlockNote)")
    Write-Note 'failed-then-success not tested: the successful logon could not be performed'
}
Add-Result 'no finding for below-threshold failures' (@($report.findings | Where-Object { Test-EvidenceField $_ 'TargetUserName' $GhostUser }).Count -eq 0) ''

$ids = @($report.findings | ForEach-Object { $_.evidence } | ForEach-Object { $_.record_id } | Sort-Object -Unique)
$missing = @($ids | Where-Object {
    $found = & wevtutil.exe qe Security "/q:*[System[EventRecordID=$_]]" /c:1 /f:xml
    -not $found
})
Add-Result 'evidence record IDs exist in the live Security log' ($missing.Count -eq 0) "$($ids.Count) checked"
$other = @($report.findings | Where-Object {
    -not ((Test-EvidenceField $_ 'TargetUserName' $TestUser) -or (Test-EvidenceField $_ 'MemberSid' $testSid))
}).Count
$results.Add("INFO  other findings in the test window (unrelated activity): $other")

# --- 6. Optional baseline ---------------------------------------------------------
if ($IncludeBaseline) {
    Write-Section '6. Baseline: previous 24 hours of normal activity'
    $baselineXml = Join-Path $outDir 'baseline-events.xml'
    $baselineReport = Join-Path $outDir 'baseline-report.json'
    $baselineQuery = "*[System[TimeCreated[@SystemTime>='$(Format-XPathTime $start.AddHours(-24))' and @SystemTime<'$(Format-XPathTime $start)']]]"
    Export-SecurityEvents $baselineQuery $baselineXml
    $elapsed = Measure-Command { & $Nyyrikki scan $baselineXml --json --out $baselineReport | Out-Null }
    $baseline = Get-Content -Raw -Path $baselineReport | ConvertFrom-Json
    $byRule = ($baseline.findings | Group-Object rule_id | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    if (-not $byRule) { $byRule = 'none' }
    $results.Add("INFO  baseline: $($baseline.counts.events) events scanned in $([math]::Round($elapsed.TotalSeconds, 2)) s; findings: $byRule")
    Write-Note "Baseline: $($baseline.counts.events) events, $([math]::Round($elapsed.TotalSeconds, 2)) s, findings: $byRule"
    Write-Note "Review them with: .venv\Scripts\nyyrikki scan `"$baselineXml`""
}

# --- 7. Summary (safe to share: no names, IPs, SIDs or event content) ---------------
$summaryPath = Join-Path $outDir 'results.txt'
$overall = 'FAIL'; if ($allPass) { $overall = 'PASS' }
$header = @(
    "Nyyrikki real-world test: $overall",
    "Date (UTC): $($start.ToString('yyyy-MM-dd HH:mm'))",
    "Nyyrikki: $(& $Nyyrikki --version)",
    "Windows build: $($os.BuildNumber); PowerShell $($PSVersionTable.PSVersion)",
    "Audit policy temporarily changed: $([bool]$auditBackup)",
    ''
)
($header + $results) | Out-File -FilePath $summaryPath -Encoding utf8

Write-Section "Overall: $overall"
Write-Host "Shareable summary (no personal data): $summaryPath"
Write-Host "Sensitive raw exports and reports:   $outDir"
Write-Host 'These contain user names, computer names and event details. Keep them local, and delete'
Write-Host 'the folder when you no longer need it.'
if ($allPass) { exit 0 } else { exit 1 }
