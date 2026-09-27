#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Module-scope state.
#   Contexts  : tenantId -> context object, populated by Connect-MtTenant
#   ActiveRun : the run started by Start-MtRun, consumed by Write-MtLog
#   Runs      : completed runs, newest last
# ---------------------------------------------------------------------------
$script:MtGraphState = @{
    Contexts  = @{}
    ActiveRun = $null
    Runs      = (New-Object System.Collections.ArrayList)
}

$script:MtGraphIsCore = ($PSVersionTable.PSVersion.Major -ge 6)

$exported = New-Object System.Collections.ArrayList

foreach ($folder in @('Private', 'Public')) {
    $folderPath = Join-Path -Path $PSScriptRoot -ChildPath $folder
    if (-not (Test-Path -LiteralPath $folderPath)) {
        continue
    }

    $scriptFiles = Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' -File | Sort-Object -Property Name
    foreach ($scriptFile in $scriptFiles) {
        . $scriptFile.FullName

        if ($folder -eq 'Public') {
            $null = $exported.Add($scriptFile.BaseName)
        }
    }
}

# Public file names are groupings, not function names, so export from the
# manifest's FunctionsToExport instead of from file names.
$manifestPath = Join-Path -Path $PSScriptRoot -ChildPath 'MtGraph.psd1'
if (Test-Path -LiteralPath $manifestPath) {
    $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
    Export-ModuleMember -Function $manifest.FunctionsToExport
}
else {
    Export-ModuleMember -Function '*-Mt*'
}
