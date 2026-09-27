#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end test of MtAzurePosture against the local ARM test double.

.DESCRIPTION
    Start-FakeArm.py must be listening on 127.0.0.1:8098 before this runs.
#>

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $repoRoot 'MtGraph/MtGraph.psd1') -Force
Import-Module (Join-Path $repoRoot 'MtAzurePosture/MtAzurePosture.psd1') -Force

$artifactRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'MtAzureTests'

$ctx = New-MtTenantContext -TenantId 'contoso.onmicrosoft.com' -ClientId 'app-id' -DeviceCode `
    -Name 'Contoso' -ArtifactRoot $artifactRoot
$ctx.Endpoints.ResourceManager = 'http://127.0.0.1:8098'
$ctx.Tokens['ResourceManager'] = @{
    AccessToken  = 'fake-arm-token'
    RefreshToken = ''
    AcquiredOn   = [DateTimeOffset]::UtcNow
    ExpiresOn    = ([DateTimeOffset]::UtcNow).AddHours(1)
}

Write-Host '== 1. Token cache is per-audience =='
'graphSlotEmpty={0} armSlotPopulated={1} slots={2}' -f `
    [string]::IsNullOrWhiteSpace($ctx.Tokens['Graph'].AccessToken),
    (-not [string]::IsNullOrWhiteSpace($ctx.Tokens['ResourceManager'].AccessToken)),
    ((@($ctx.Tokens.Keys) | Sort-Object) -join ',')
'armEndpoint={0}' -f (Get-MtAzureSubscription -Context $ctx | Select-Object -First 1).DisplayName

Write-Host ''
Write-Host '== 2. ARM requires an explicit api-version =='
try {
    $null = Invoke-MtGraphRequest -Context $ctx -Service ResourceManager -Uri 'subscriptions'
    'NO ERROR - unexpected'
}
catch {
    'rejected: {0}' -f $_.Exception.Message
}

Write-Host ''
Write-Host '== 3. Full sweep (all reads) =='
$run = Start-MtRun -Name 'AzurePostureSweep' -Context @($ctx) -Ticket 'PROJ-118'
$posture = Get-MtAzurePosture -Context $ctx
$sub = @($posture.Subscriptions)[0]
'subscription={0} nsgs={1} storage={2} vms={3} workspaces={4}' -f `
    $sub.DisplayName, $sub.Network.NsgCount, @($sub.Storage.Accounts).Count,
    @($sub.Compute.VirtualMachines).Count, @($sub.Monitoring.Workspaces).Count
'exposures={0} orphanIps={1} orphanNics={2} unattachedDisks={3}' -f `
    @($sub.Network.Exposures).Count, @($sub.Network.OrphanedIps).Count,
    @($sub.Network.OrphanedNics).Count, @($sub.Compute.UnattachedDisks).Count
'vmBackupState=' + ((@($sub.Compute.VirtualMachines) | ForEach-Object { '{0}:{1}' -f $_.Name, $_.BackedUp }) -join ' ')
'roleNamesResolved={0} coverageGaps={1}' -f $sub.Rbac.DefinitionsResolved, @($posture.NotChecked).Count

Write-Host ''
Write-Host '== 4. Port range expansion caught the hidden port =='
$rangeRule = @($sub.Network.Exposures | Where-Object { $_.RuleName -eq 'allow-range' })
'rangeRuleFound={0} expandedPorts={1}' -f ($rangeRule.Count -gt 0), ((@($rangeRule[0].ExposedPorts) | Sort-Object) -join ',')
$httpsRule = @($sub.Network.Exposures | Where-Object { $_.RuleName -eq 'allow-https' })
'port443NotFlagged={0}' -f (@($httpsRule[0].ExposedPorts).Count -eq 0)

Write-Host ''
Write-Host '== 5. Findings =='
$findings = @(Get-MtAzureFinding -Posture $posture)
$findings | Where-Object { @('Critical', 'High', 'Medium') -contains $_.Severity } |
    Format-Table Severity, Category, Resource, Title -AutoSize | Out-String -Width 200
'total={0} critical={1} high={2} medium={3}' -f $findings.Count,
    @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count,
    @($findings | Where-Object { $_.Severity -eq 'High' }).Count,
    @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count

Write-Host ''
Write-Host '== 6. Clean storage account produced no findings =='
'stappsecureFindings={0}' -f @($findings | Where-Object { $_.Resource -eq 'stappsecure' }).Count

Write-Host ''
Write-Host '== 7. Denied scope became a gap, not a clean result =='
$policyGap = @($findings | Where-Object { $_.Category -eq 'Coverage gap' -and $_.Title -like '*Policy*' })
'policyGapReported={0}' -f ($policyGap.Count -gt 0)
@($posture.NotChecked) | ForEach-Object { ' gap: {0} / {1}' -f $_.Source, $_.Reason }

Write-Host ''
Write-Host '== 8. Sweep issued zero writes =='
'changeCount={0} whatIfCount={1}' -f $run.Counters.Change, $run.Counters.WhatIf

Write-Host ''
Write-Host '== 9. Report =='
$report = Export-MtAzureReport -Posture $posture -Path $run.Path -Ticket 'PROJ-118' -Finding $findings
$null = Complete-MtRun -Run $run -Outcome 'Completed'
Get-ChildItem $run.Path | Select-Object -ExpandProperty Name
