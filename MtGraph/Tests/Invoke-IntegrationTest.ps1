$ErrorActionPreference = 'Stop'
Import-Module $(Join-Path (Split-Path -Parent $PSScriptRoot) 'MtGraph.psd1') -Force

function New-TestContext([string]$Name, [string]$Tenant) {
    $c = New-MtTenantContext -TenantId $Tenant -ClientId 'app-id' -DeviceCode -Name $Name -ArtifactRoot (Join-Path ([System.IO.Path]::GetTempPath()) 'MtGraphTests')
    $c.Endpoints.Graph = 'http://127.0.0.1:8099'
    $c.Token.AccessToken = 'fake-token'
    $c.Token.ExpiresOn   = ([DateTimeOffset]::UtcNow).AddHours(1)
    return $c
}
$ctx = New-TestContext 'Contoso' 'contoso.onmicrosoft.com'

Write-Host "-- 429 with Retry-After, then 2-page paging --"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$users = @(Invoke-MtGraphRequest -Context $ctx -Uri 'users' -All -Verbose:$false)
$sw.Stop()
"ids={0} count={1} elapsed={2}s (backoff honored: {3})" -f (($users | ForEach-Object { $_.id }) -join ','), $users.Count, [math]::Round($sw.Elapsed.TotalSeconds,1), ($sw.Elapsed.TotalSeconds -ge 1)

Write-Host "`n-- MaxPages stops pagination --"
$ctx2 = New-TestContext 'Contoso2' 'contoso.onmicrosoft.com'
"firstPageOnly={0}" -f @(Invoke-MtGraphRequest -Context $ctx2 -Uri 'users' -All -MaxPages 1).Count

Write-Host "`n-- 403 -> structured ErrorRecord --"
try { $null = Invoke-MtGraphRequest -Context $ctx -Uri 'directoryRoles' }
catch {
    "errorId={0}"   -f $_.FullyQualifiedErrorId.Split(',')[0]
    "message={0}"   -f $_.Exception.Message
    "requestId={0} graphCode={1} status={2}" -f $_.Exception.Data["MtGraph"].requestId, $_.Exception.Data["MtGraph"].graphCode, $_.Exception.Data["MtGraph"].statusCode
}

Write-Host "`n-- Connect-MtTenant resolves identity + capabilities --"
$live = New-MtTenantContext -TenantId 'contoso.onmicrosoft.com' -ClientId 'app-id' -DeviceCode -ArtifactRoot (Join-Path ([System.IO.Path]::GetTempPath()) 'MtGraphTests'); $live.Endpoints.Graph = 'http://127.0.0.1:8099'; $live.Token.AccessToken = 'fake-token'; $live.Token.ExpiresOn = ([DateTimeOffset]::UtcNow).AddHours(1)
$null = Connect-MtTenant -Context $live
"Name={0}" -f $live.Name
"TenantId={0}" -f $live.TenantId
"DefaultDomain={0}" -f $live.DefaultDomain
$caps = [pscustomobject]$live.Capabilities
"E5Suite={0} EntraIdP2={1} Intune={2} DefenderP2={3} DefenderCloudApps(disabled plan)={4}" -f $caps.E5Suite, $caps.EntraIdP2, $caps.Intune, $caps.DefenderForOfficeP2, $caps.DefenderForCloudApps
"registered={0}" -f (Get-MtContext).Count

Write-Host "`n-- write gate: read-only refuses, armed executes --"
$run = Start-MtRun -Name 'WriteGate' -Context @($live) -Ticket 'INC-042'
$sim = Invoke-MtGraphRequest -Context $live -Method POST -Uri 'users/jdoe/revokeSignInSessions'
"readonly -> simulated={0}" -f $sim.Simulated
$null = Set-MtWriteMode -Context $live -AllowWrites -Confirm:$false
$real = Invoke-MtGraphRequest -Context $live -Method POST -Uri 'users/jdoe/revokeSignInSessions' -Confirm:$false
"armed -> whatIfCount={0} changeCount={1}" -f $run.Counters.WhatIf, $run.Counters.Change
$done = Complete-MtRun -Run $run -Outcome 'Completed'
Get-Content (Join-Path $done.Path 'summary.md') -Raw | Select-String -Pattern 'Change:|Changes made|revokeSignInSessions' | ForEach-Object { $_.Line.Trim() }

Write-Host "`n-- fleet fan-out isolates failure --"
$results = @((New-TestContext 'Alpha' 'a.onmicrosoft.com'), (New-TestContext 'Bravo' 'b.onmicrosoft.com')) |
    Invoke-MtForEachTenant -ScriptBlock {
        param($Context)
        if ($Context.Name -eq 'Bravo') { $null = Invoke-MtGraphRequest -Context $Context -Uri 'directoryRoles' }
        @(Invoke-MtGraphRequest -Context $Context -Uri 'organization').displayName
    }
$results | Format-Table Tenant, Success, Output, DurationMs -AutoSize | Out-String -Width 200
$failed = @($results | Where-Object { -not $_.Success })[0]
"failedTenant={0} stackCaptured={1}" -f $failed.Tenant, (-not [string]::IsNullOrWhiteSpace($failed.StackTrace))
"error={0}" -f $failed.Error
