#Requires -Version 5.1
<#
.SYNOPSIS
    Ninety-second walkthrough of the MtGraph toolchain. Runs entirely offline.

.DESCRIPTION
    No network, no tenant, no local server, no Python, no elevation. HTTP
    responses come from recorded fixtures; everything above the transport is
    the real module code.

.PARAMETER Part
    Which section to run. 'All' is the full walkthrough.

.PARAMETER Pause
    Wait for a keypress between sections. Use this when screen-sharing.

.EXAMPLE
    .\Invoke-Demo.ps1

.EXAMPLE
    .\Invoke-Demo.ps1 -Pause -Part Containment
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'Containment', 'Azure')]
    [string]$Part = 'All',

    [switch]$Pause,

    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The modules warn on every armed context and every containment step. That is
# correct behaviour in operation and noise in a walkthrough; the narration
# below surfaces the same facts deliberately.
$WarningPreference = 'SilentlyContinue'

$repoRoot = Split-Path -Parent $PSScriptRoot
$demoRoot = $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path ([System.IO.Path]::GetTempPath()) ('MtDemo-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

# --------------------------------------------------------------- output ---
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('  ' + ('-' * 68)) -ForegroundColor DarkGray
    Write-Host ('  {0}' -f $Title) -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 68)) -ForegroundColor DarkGray
    Write-Host ''
}

function Write-Step {
    param([string]$Text)
    Write-Host ('  > {0}' -f $Text) -ForegroundColor White
}

function Write-Note {
    param([string]$Text)
    Write-Host ('    {0}' -f $Text) -ForegroundColor DarkGray
}

function Write-Verdict {
    param([string]$Text, [bool]$Good = $true)
    $colour = 'Green'
    $mark = 'PASS'
    if (-not $Good) {
        $colour = 'Yellow'
        $mark = 'WARN'
    }
    Write-Host ('    [{0}] {1}' -f $mark, $Text) -ForegroundColor $colour
}

function Wait-Step {
    if ($Pause) {
        Write-Host ''
        Write-Host '    [enter to continue]' -ForegroundColor DarkGray
        $null = Read-Host
    }
}

function Show-Findings {
    param($Findings, [string[]]$Severities = @('Critical', 'High'))

    foreach ($finding in @($Findings | Where-Object { $Severities -contains $_.Severity })) {
        $colour = 'Yellow'
        if ($finding.Severity -eq 'Critical') {
            $colour = 'Red'
        }
        Write-Host ('    {0,-9} {1,-20} {2}' -f $finding.Severity, $finding.Category, $finding.Title) -ForegroundColor $colour
    }
}

# ---------------------------------------------------------------- setup ---
Write-Host ''
Write-Host '  MtGraph toolchain demo' -ForegroundColor Cyan
Write-Host '  Multi-tenant Microsoft 365 and Azure operations tooling' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  This runs OFFLINE against recorded API responses.' -ForegroundColor DarkYellow
Write-Host '  The transport is simulated; every layer above it is real module code -' -ForegroundColor DarkGray
Write-Host '  token handling, retry, paging, the write gate, findings, reports.' -ForegroundColor DarkGray

Import-Module (Join-Path $repoRoot 'MtGraph/MtGraph.psd1') -Force
Import-Module (Join-Path $repoRoot 'MtContainment/MtContainment.psd1') -Force
Import-Module (Join-Path $repoRoot 'MtAzurePosture/MtAzurePosture.psd1') -Force
. (Join-Path $demoRoot 'MtDemoTransport.ps1')

Install-MtDemoTransport -FixtureRoot (Join-Path $demoRoot 'Fixtures')

$context = New-MtDemoContext -ArtifactRoot $OutputPath
$null = Connect-MtTenant -Context $context

Write-Host ''
Write-Note ('Tenant: {0}   Cloud: {1}   Write mode: {2}' -f $context.Name, $context.Cloud, $(if ($context.WhatIfMode) { 'READ-ONLY' } else { 'ARMED' }))
Wait-Step

# ----------------------------------------------------------- containment ---
if ($Part -eq 'All' -or $Part -eq 'Containment') {

    Write-Section 'Part 1 - Account compromise: investigate'
    Write-Step 'A finance user reports a supplier never received their invoice reply.'
    Write-Note 'One read-only sweep replaces about an hour across four admin portals.'
    Write-Host ''

    Clear-MtDemoWrite
    $run = Start-MtRun -Name 'AccountContainment' -Context @($context) -Ticket 'INC-4471'
    $investigation = Get-MtUserInvestigation -Context $context -User 'jdoe@contoso.com' -Days 7

    Write-Note ('Collected: {0} sign-ins, {1} inbox rules, {2} OAuth grants, {3} auth methods, {4} directory role(s)' -f `
            @($investigation.SignIns).Count, @($investigation.InboxRules).Count, @($investigation.OAuthGrants).Count,
        @($investigation.AuthMethods).Count, @($investigation.Privilege.DirectoryRoles).Count)
    Write-Verdict ('Writes issued during investigation: {0}' -f @(Get-MtDemoWrite).Count) ((@(Get-MtDemoWrite).Count) -eq 0)
    Wait-Step

    Write-Section 'Part 2 - Findings, not a data dump'
    $findings = @(Get-MtInvestigationFinding -Investigation $investigation)
    Show-Findings -Findings $findings
    Write-Host ''
    Write-Note ('{0} findings total: {1} Critical, {2} High, {3} Medium' -f $findings.Count,
        @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count,
        @($findings | Where-Object { $_.Severity -eq 'High' }).Count,
        @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count)
    Write-Host ''
    Write-Note 'The two that matter most are the two most runbooks forget:'
    Write-Note '  attacker-registered MFA, and OAuth consent. Both survive a password reset.'
    Wait-Step

    Write-Section 'Part 3 - Coverage gaps are reported, not hidden'
    foreach ($gap in @($investigation.NotChecked)) {
        Write-Note ('{0}: {1}' -f $gap.Source, $gap.Reason)
    }
    Write-Host ''
    Write-Note 'A gap you disclose is evidence. A gap you leave silent is a false all-clear.'
    Wait-Step

    Write-Section 'Part 4 - Dry run: the context is still read-only'
    Clear-MtDemoWrite
    $dryRun = Invoke-MtAccountContainment -Context $context -Investigation $investigation -Scope Full -Confirm:$false
    Write-Note ('Mode: {0}   Applied: {1}   Simulated: {2}' -f $dryRun.Mode, $dryRun.AppliedCount, $dryRun.SimulatedCount)
    Write-Verdict ('Writes that reached the wire: {0}' -f @(Get-MtDemoWrite).Count) ((@(Get-MtDemoWrite).Count) -eq 0)
    Write-Host ''
    Write-Note 'Same code path as the real thing. Safe to show a client before arming it.'
    Wait-Step

    Write-Section 'Part 5 - Armed: containment in the order that actually works'
    Clear-MtDemoWrite
    $null = Set-MtWriteMode -Context $context -AllowWrites -Confirm:$false
    $result = Invoke-MtAccountContainment -Context $context -Investigation $investigation -Scope Full -Confirm:$false

    Write-Host ''
    foreach ($write in @(Get-MtDemoWrite)) {
        $short = $write.Path -replace '/v1\.0/', '' -replace '7f3c1a90-5d21-4b8e-9a44-11c2e6d70b31', '{user}'
        Write-Host ('    {0,-7} {1}' -f $write.Method, $short) -ForegroundColor Gray
    }
    Write-Host ''
    Write-Note 'Disable, strip hostile MFA, reset, THEN revoke sessions, then rules, then consent.'
    Write-Note 'Revoke runs last: a token minted between a revocation and a later'
    Write-Note 'password change survives. Revoke-then-reset leaves a window open.'
    Wait-Step

    Write-Section 'Part 6 - The generated password never touches the log'
    $reset = @($result.Actions | Where-Object { $_.Action -eq 'ResetPassword' })[0]
    $logText = Get-Content -LiteralPath $run.LogPath -Raw
    Write-Verdict ('Password present in run.jsonl: {0}' -f $logText.Contains($reset.Password)) (-not $logText.Contains($reset.Password))
    Write-Verdict ('Redaction marker written instead: {0}' -f $logText.Contains('[redacted]')) ($logText.Contains('[redacted]'))
    Write-Note 'run.jsonl gets attached to tickets. A credential must never be in it.'
    Wait-Step

    Write-Section 'Part 7 - The run documents itself'
    $report = Export-MtInvestigationReport -Investigation $investigation -Containment $result `
        -Path $run.Path -Ticket 'INC-4471' -Finding $findings
    $null = Complete-MtRun -Run $run -Outcome 'Contained'

    foreach ($file in (Get-ChildItem -LiteralPath $run.Path | Sort-Object Name)) {
        Write-Note ('{0,-22} {1,7:N0} bytes' -f $file.Name, $file.Length)
    }
    Write-Host ''
    Write-Note 'report.md goes in the ticket. No one writes case notes by hand.'
    Write-Host ('    {0}' -f $report.ReportPath) -ForegroundColor Green
    Wait-Step

    $null = Set-MtWriteMode -Context $context -ReadOnly -Confirm:$false
}

# ----------------------------------------------------------------- azure ---
if ($Part -eq 'All' -or $Part -eq 'Azure') {

    Write-Section 'Part 8 - Azure posture sweep: same pipeline, different API'
    Write-Step 'Graph and ARM are different token audiences, so the context caches one per service.'
    Write-Note ('Token slots held: {0}' -f ((@($context.Tokens.Keys) | Sort-Object) -join ', '))
    Write-Host ''

    Clear-MtDemoWrite
    $azureRun = Start-MtRun -Name 'AzurePostureSweep' -Context @($context) -Ticket 'PROJ-118'
    $posture = Get-MtAzurePosture -Context $context
    $azureFindings = @(Get-MtAzureFinding -Posture $posture)

    Show-Findings -Findings $azureFindings -Severities @('Critical', 'High', 'Medium')
    Write-Host ''
    Write-Note ('{0} findings across {1} subscription(s).' -f $azureFindings.Count, @($posture.Subscriptions).Count)
    Write-Verdict ('Writes issued by the sweep: {0}' -f @(Get-MtDemoWrite).Count) ((@(Get-MtDemoWrite).Count) -eq 0)
    Wait-Step

    Write-Section 'Part 9 - Two details that separate a real tool from a checklist'
    $sub = @($posture.Subscriptions)[0]

    $rangeRule = @($sub.Network.Exposures | Where-Object { $_.RuleName -eq 'allow-range' })
    if ($rangeRule.Count -gt 0) {
        Write-Step 'Port ranges are expanded, not string-matched.'
        Write-Note ('Rule "allow-range" opens 1000-4000; that resolves to {0}' -f ((@($rangeRule[0].ExposedPorts) | Sort-Object) -join ', '))
        Write-Note 'A range that swallows SQL is as exposed as one naming it, and easier to miss by eye.'
    }

    Write-Host ''
    Write-Step 'A denied scope is a gap, not a clean pass.'
    foreach ($gap in @($posture.NotChecked)) {
        Write-Note ('{0}: {1}' -f $gap.Source, $gap.Reason)
    }
    Write-Note 'Contributor cannot read Policy Insights. The report says so rather than showing green.'

    Write-Host ''
    Write-Step 'And it does not cry wolf.'
    $cleanFindings = @($azureFindings | Where-Object { $_.Resource -eq 'stappsecure' }).Count
    Write-Verdict ('Findings against the correctly configured storage account: {0}' -f $cleanFindings) ($cleanFindings -eq 0)
    Wait-Step

    $azureReport = Export-MtAzureReport -Posture $posture -Path $azureRun.Path -Ticket 'PROJ-118' -Finding $azureFindings
    $null = Complete-MtRun -Run $azureRun -Outcome 'Completed'
    Write-Host ('    {0}' -f $azureReport.ReportPath) -ForegroundColor Green
}

# --------------------------------------------------------------- wrap up ---
Write-Section 'Done'
Write-Note ('Artifacts written to: {0}' -f $OutputPath)
Write-Host ''
Write-Note 'Everything above ran offline against recorded responses.'
Write-Note 'Against a real tenant the only change is the transport - same code, same output.'
Write-Host ''
