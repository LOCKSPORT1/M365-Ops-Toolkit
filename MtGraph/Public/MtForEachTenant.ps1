function Invoke-MtForEachTenant {
    <#
    .SYNOPSIS
        Runs a scriptblock against many tenant contexts, isolating failures.

    .DESCRIPTION
        This is the multi-tenant payoff: one customer's expired secret, revoked
        consent or throttled tenant must not abort a fleet-wide report.

        Each tenant yields a result object with Success, Output, Error and
        Duration. Errors are logged with the full ScriptStackTrace captured
        before anything else touches $_ .

        The scriptblock receives the context as $args[0]; declare
        param($Context) inside it for readability.

    .EXAMPLE
        $results = $book | Invoke-MtForEachTenant -ScriptBlock {
            param($Context)
            Invoke-MtGraphRequest -Context $Context -Uri 'identity/conditionalAccess/policies' -All |
                Select-Object @{n='Tenant';e={$Context.Name}}, displayName, state
        }

        $results | Where-Object { -not $_.Success } | Select-Object Tenant, Error
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Context,

        [Parameter(Mandatory, Position = 0)]
        [scriptblock]$ScriptBlock,

        [switch]$StopOnError,

        [switch]$ShowProgress
    )

    begin {
        $collected = New-Object System.Collections.ArrayList
    }

    process {
        foreach ($item in $Context) {
            $null = $collected.Add($item)
        }
    }

    end {
        $total = $collected.Count
        $index = 0

        foreach ($item in $collected) {
            $index++

            if ($ShowProgress) {
                $percent = 0
                if ($total -gt 0) {
                    $percent = [int](($index / $total) * 100)
                }
                Write-Progress -Activity 'MtGraph fleet run' -Status ('{0} ({1} of {2})' -f $item.Name, $index, $total) -PercentComplete $percent
            }

            $result = [ordered]@{
                PSTypeName = 'MtGraph.TenantResult'
                Tenant     = $item.Name
                TenantId   = $item.TenantId
                Success    = $false
                Output     = $null
                Error      = ''
                StackTrace = ''
                DurationMs = 0
            }

            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $failure = $null

            try {
                $result.Output = & $ScriptBlock $item
                $result.Success = $true
            }
            catch {
                # Capture the stack trace first; anything else clobbers $_ .
                $capturedStack = $_.ScriptStackTrace
                $failure = $_

                $result.Error = $_.Exception.Message
                $result.StackTrace = $capturedStack

                Write-MtLog -Level 'Error' -Context $item -Message ('Fleet step failed: {0}' -f $_.Exception.Message) -StackTrace $capturedStack
            }
            finally {
                $stopwatch.Stop()
                $result.DurationMs = [int]$stopwatch.Elapsed.TotalMilliseconds
            }

            [pscustomobject]$result

            if ($null -ne $failure -and $StopOnError) {
                if ($ShowProgress) {
                    Write-Progress -Activity 'MtGraph fleet run' -Completed
                }

                # Cleanup is done; the rethrow stands alone.
                throw $failure
            }
        }

        if ($ShowProgress) {
            Write-Progress -Activity 'MtGraph fleet run' -Completed
        }
    }
}
