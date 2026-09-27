function Start-MtRun {
    <#
    .SYNOPSIS
        Opens a run: a folder, a structured log, and an operator/time stamp.

    .DESCRIPTION
        Every tool built on this module should open a run and close it. The
        artifact is the point — it is what gets attached to the ticket, what
        proves what was touched in a client tenant, and what a reviewer reads
        six months later.

    .EXAMPLE
        $run = Start-MtRun -Name 'AccountContainment' -Context $ctx
        try { ... } finally { Complete-MtRun -Run $run }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [object[]]$Context,

        [string]$ArtifactRoot,

        [string]$Ticket,

        [hashtable]$Metadata = @{}
    )

    if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
        if ($null -ne $Context -and $Context.Count -gt 0) {
            $ArtifactRoot = $Context[0].ArtifactRoot
        }
        else {
            $ArtifactRoot = Get-MtDefaultArtifactRoot
        }
    }

    $runId = [guid]::NewGuid().ToString()
    $startedOn = [DateTimeOffset]::UtcNow
    $safeName = ($Name -replace '[^A-Za-z0-9\-_]', '_')
    $folderName = '{0}_{1}_{2}' -f $startedOn.ToString('yyyyMMdd-HHmmss'), $safeName, $runId.Substring(0, 8)
    $runPath = Join-Path -Path $ArtifactRoot -ChildPath $folderName

    $null = New-Item -Path $runPath -ItemType Directory -Force

    $tenantSummaries = @()
    foreach ($item in @($Context)) {
        if ($null -eq $item) {
            continue
        }

        $tenantSummaries += [pscustomobject]@{
            name       = $item.Name
            tenantId   = $item.TenantId
            cloud      = $item.Cloud
            writeMode  = $(if ($item.WhatIfMode) { 'read-only' } else { 'armed' })
            authMode   = $item.AuthMode
            clientId   = $item.ClientId
        }
    }

    $run = [pscustomobject]@{
        PSTypeName  = 'MtGraph.Run'
        RunId       = $runId
        Name        = $Name
        Ticket      = $Ticket
        StartedOn   = $startedOn
        CompletedOn = $null
        Operator    = [Environment]::UserName
        Machine     = [Environment]::MachineName
        Path        = $runPath
        LogPath     = (Join-Path -Path $runPath -ChildPath 'run.jsonl')
        Tenants     = $tenantSummaries
        Metadata    = $Metadata
        Counters    = @{ Info = 0; Warning = 0; Error = 0; WhatIf = 0; Change = 0 }
        Records     = (New-Object System.Collections.ArrayList)
    }

    $script:MtGraphState.ActiveRun = $run

    Write-MtLog -Message ('Run "{0}" started by {1} on {2}.' -f $Name, $run.Operator, $run.Machine) -Data @{
        runId   = $runId
        ticket  = $Ticket
        tenants = $tenantSummaries
    }

    return $run
}

function Write-MtLog {
    <#
    .SYNOPSIS
        Appends a structured record to the active run and mirrors it to the
        appropriate PowerShell stream.

    .DESCRIPTION
        Safe to call with no active run — it degrades to stream output only, so
        library functions can log unconditionally.

        Level 'Change' marks an actual mutation; 'WhatIf' marks one that was
        refused by read-only mode. Keeping them distinct is what makes the
        summary honest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error', 'WhatIf', 'Change')]
        [string]$Level = 'Info',

        [object]$Context,

        [hashtable]$Data,

        [string]$StackTrace
    )

    $tenantName = ''
    $tenantId = ''
    if ($null -ne $Context) {
        $tenantName = [string]$Context.Name
        $tenantId = [string]$Context.TenantId
    }

    $record = [ordered]@{
        timestamp  = ([DateTimeOffset]::UtcNow).ToString('o')
        level      = $Level
        tenant     = $tenantName
        tenantId   = $tenantId
        message    = $Message
        data       = $Data
        stackTrace = $StackTrace
    }

    $run = $script:MtGraphState.ActiveRun

    if ($null -ne $run) {
        $record['runId'] = $run.RunId
        $null = $run.Records.Add([pscustomobject]$record)

        if ($run.Counters.ContainsKey($Level)) {
            $run.Counters[$Level] = $run.Counters[$Level] + 1
        }

        try {
            $line = ([pscustomobject]$record) | ConvertTo-Json -Depth 10 -Compress
            Add-Content -LiteralPath $run.LogPath -Value $line -Encoding UTF8
        }
        catch {
            Write-Verbose ('Could not append to run log: {0}' -f $_.Exception.Message)
        }
    }

    $prefix = $(if ([string]::IsNullOrWhiteSpace($tenantName)) { '' } else { ('[{0}] ' -f $tenantName) })
    $line = '{0}{1}' -f $prefix, $Message

    if ($Level -eq 'Error') {
        Write-Verbose $line
    }
    elseif ($Level -eq 'Warning') {
        Write-Warning $line
    }
    else {
        Write-Verbose $line
    }
}

function Complete-MtRun {
    <#
    .SYNOPSIS
        Closes a run and writes summary.json and summary.md beside the log.

    .DESCRIPTION
        summary.md is the part that goes in the ticket. summary.json is the part
        a later report or dashboard reads.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ValueFromPipeline)]
        [object]$Run,

        [string]$Outcome = 'Completed',

        [string]$Notes
    )

    process {
        if ($null -eq $Run) {
            $Run = $script:MtGraphState.ActiveRun
        }

        if ($null -eq $Run) {
            Write-Verbose 'Complete-MtRun called with no active run; nothing to do.'
            return
        }

        $Run.CompletedOn = [DateTimeOffset]::UtcNow
        $duration = $Run.CompletedOn - $Run.StartedOn

        $summary = [ordered]@{
            runId       = $Run.RunId
            name        = $Run.Name
            ticket      = $Run.Ticket
            outcome     = $Outcome
            notes       = $Notes
            operator    = $Run.Operator
            machine     = $Run.Machine
            startedOn   = $Run.StartedOn.ToString('o')
            completedOn = $Run.CompletedOn.ToString('o')
            durationSec = [math]::Round($duration.TotalSeconds, 2)
            tenants     = $Run.Tenants
            counters    = $Run.Counters
            metadata    = $Run.Metadata
        }

        $summaryJsonPath = Join-Path -Path $Run.Path -ChildPath 'summary.json'
        $summaryMdPath = Join-Path -Path $Run.Path -ChildPath 'summary.md'

        ([pscustomobject]$summary) | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryJsonPath -Encoding UTF8

        $markdown = New-Object System.Text.StringBuilder
        $null = $markdown.AppendLine(('# {0}' -f $Run.Name))
        $null = $markdown.AppendLine('')
        $null = $markdown.AppendLine(('- **Run id:** {0}' -f $Run.RunId))
        if (-not [string]::IsNullOrWhiteSpace($Run.Ticket)) {
            $null = $markdown.AppendLine(('- **Ticket:** {0}' -f $Run.Ticket))
        }
        $null = $markdown.AppendLine(('- **Operator:** {0} on {1}' -f $Run.Operator, $Run.Machine))
        $null = $markdown.AppendLine(('- **Started (UTC):** {0}' -f $Run.StartedOn.ToString('yyyy-MM-dd HH:mm:ss')))
        $null = $markdown.AppendLine(('- **Duration:** {0}s' -f [math]::Round($duration.TotalSeconds, 2)))
        $null = $markdown.AppendLine(('- **Outcome:** {0}' -f $Outcome))
        $null = $markdown.AppendLine('')

        if (@($Run.Tenants).Count -gt 0) {
            $null = $markdown.AppendLine('## Tenants')
            $null = $markdown.AppendLine('')
            $null = $markdown.AppendLine('| Tenant | Tenant id | Write mode |')
            $null = $markdown.AppendLine('| --- | --- | --- |')
            foreach ($tenant in @($Run.Tenants)) {
                $null = $markdown.AppendLine(('| {0} | {1} | {2} |' -f $tenant.name, $tenant.tenantId, $tenant.writeMode))
            }
            $null = $markdown.AppendLine('')
        }

        $null = $markdown.AppendLine('## Counters')
        $null = $markdown.AppendLine('')
        foreach ($key in @('Change', 'WhatIf', 'Warning', 'Error', 'Info')) {
            $null = $markdown.AppendLine(('- {0}: {1}' -f $key, $Run.Counters[$key]))
        }
        $null = $markdown.AppendLine('')

        $changes = @($Run.Records | Where-Object { $_.level -eq 'Change' })
        if ($changes.Count -gt 0) {
            $null = $markdown.AppendLine('## Changes made')
            $null = $markdown.AppendLine('')
            foreach ($change in $changes) {
                $null = $markdown.AppendLine(('- `{0}` {1} — {2}' -f $change.timestamp, $change.tenant, $change.message))
            }
            $null = $markdown.AppendLine('')
        }

        $problems = @($Run.Records | Where-Object { @('Warning', 'Error') -contains $_.level })
        if ($problems.Count -gt 0) {
            $null = $markdown.AppendLine('## Warnings and errors')
            $null = $markdown.AppendLine('')
            foreach ($problem in $problems) {
                $null = $markdown.AppendLine(('- **{0}** {1} — {2}' -f $problem.level, $problem.tenant, $problem.message))
            }
            $null = $markdown.AppendLine('')
        }

        if (-not [string]::IsNullOrWhiteSpace($Notes)) {
            $null = $markdown.AppendLine('## Notes')
            $null = $markdown.AppendLine('')
            $null = $markdown.AppendLine($Notes)
        }

        $markdown.ToString() | Set-Content -LiteralPath $summaryMdPath -Encoding UTF8

        $null = $script:MtGraphState.Runs.Add($Run)
        $script:MtGraphState.ActiveRun = $null

        return $Run
    }
}

function Get-MtRun {
    <#
    .SYNOPSIS
        Returns the active run, or completed runs from this session.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch]$Completed
    )

    if ($Completed) {
        return @($script:MtGraphState.Runs)
    }

    return $script:MtGraphState.ActiveRun
}
