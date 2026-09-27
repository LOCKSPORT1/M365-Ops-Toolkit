#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end test of MtContainment against the local Graph test double.

.DESCRIPTION
    Start-FakeM365.py must be listening on 127.0.0.1:8099 before this runs.
#>

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $repoRoot 'MtGraph/MtGraph.psd1') -Force
Import-Module (Join-Path $repoRoot 'MtContainment/MtContainment.psd1') -Force

$artifactRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'MtContainmentTests'

function New-TestContext {
    $context = New-MtTenantContext -TenantId 'contoso.onmicrosoft.com' -ClientId 'app-id' -DeviceCode -ArtifactRoot $artifactRoot
    $context.Endpoints.Graph = 'http://127.0.0.1:8099'
    $context.Token.AccessToken = 'fake-token'
    $context.Token.ExpiresOn = ([DateTimeOffset]::UtcNow).AddHours(1)
    return $context
}

function Get-ServerWrites {
    $response = Invoke-WebRequest -Uri 'http://127.0.0.1:8099/v1.0/_writes' -Method POST -UseBasicParsing -ErrorAction Stop
    return ($response.Content | ConvertFrom-Json).value
}

Write-Host '== 1. Investigation (read-only) =='
$ctx = New-TestContext
$null = Connect-MtTenant -Context $ctx
$run = Start-MtRun -Name 'AccountContainment' -Context @($ctx) -Ticket 'INC-4471'

$investigation = Get-MtUserInvestigation -Context $ctx -User 'jdoe@contoso.com' -Days 7
'user={0} id={1}' -f $investigation.UserPrincipalName, $investigation.UserId
'signIns={0} rules={1} grants={2} methods={3}' -f @($investigation.SignIns).Count, @($investigation.InboxRules).Count, @($investigation.OAuthGrants).Count, @($investigation.AuthMethods).Count
'roles={0} ownedObjects={1} collectorErrors={2}' -f @($investigation.Privilege.DirectoryRoles).Count, @($investigation.Privilege.OwnedObjects).Count, @($investigation.Errors).Count
'folderNameResolved={0}' -f (@($investigation.InboxRules | Where-Object { $_.Id -eq 'rule-hostile-01' })[0].MoveToFolderName)
'internalForwardNotFlagged={0}' -f (@($investigation.InboxRules | Where-Object { $_.Id -eq 'rule-internal-03' })[0].ExternalRecipients).Count

Write-Host ''
Write-Host '== 2. Findings =='
$findings = @(Get-MtInvestigationFinding -Investigation $investigation)
$findings | Where-Object { @('Critical', 'High') -contains $_.Severity } |
    Format-Table Severity, Category, Title -AutoSize | Out-String -Width 160
'totalFindings={0} critical={1} high={2}' -f $findings.Count,
    @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count,
    @($findings | Where-Object { $_.Severity -eq 'High' }).Count

Write-Host ''
Write-Host '== 3. Investigation performed zero writes =='
'serverWritesAfterInvestigation={0}' -f @(Get-ServerWrites).Count

Write-Host ''
Write-Host '== 4. Containment dry run (context still read-only) =='
$dryRun = Invoke-MtAccountContainment -Context $ctx -Investigation $investigation -Scope Full -Confirm:$false
'mode={0} applied={1} simulated={2}' -f $dryRun.Mode, $dryRun.AppliedCount, $dryRun.SimulatedCount
'serverWritesAfterDryRun={0}' -f @(Get-ServerWrites).Count

Write-Host ''
Write-Host '== 5. Containment armed =='
$null = Set-MtWriteMode -Context $ctx -AllowWrites -Confirm:$false
$result = Invoke-MtAccountContainment -Context $ctx -Investigation $investigation -Scope Full -Confirm:$false
'mode={0} applied={1} simulated={2}' -f $result.Mode, $result.AppliedCount, $result.SimulatedCount
$result.Actions | Format-Table Action, Target, Simulated, Success -AutoSize | Out-String -Width 160

Write-Host '-- what actually hit the wire, in order --'
@(Get-ServerWrites) | ForEach-Object { '{0} {1}' -f $_.method, $_.path }

Write-Host ''
Write-Host '== 6. Password never lands in the run log =='
$resetAction = @($result.Actions | Where-Object { $_.Action -eq 'ResetPassword' })[0]
$password = $resetAction.Password
'passwordGenerated={0} length={1}' -f (-not [string]::IsNullOrWhiteSpace($password)), $password.Length
$logText = Get-Content -LiteralPath $run.LogPath -Raw
'passwordInRunLog={0}' -f ($logText.Contains($password))
'redactionMarkerPresent={0}' -f ($logText.Contains('[redacted]'))

Write-Host ''
Write-Host '== 7. Report =='
$report = Export-MtInvestigationReport -Investigation $investigation -Containment $result -Path $run.Path -Ticket 'INC-4471' -Finding $findings
$null = Complete-MtRun -Run $run -Outcome 'Contained'
Get-ChildItem $run.Path | Select-Object -ExpandProperty Name
Write-Host ''
Get-Content -LiteralPath $report.ReportPath -Raw
