#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($folder in @('Private', 'Public')) {
    $folderPath = Join-Path -Path $PSScriptRoot -ChildPath $folder
    if (-not (Test-Path -LiteralPath $folderPath)) {
        continue
    }

    $scriptFiles = Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' -File | Sort-Object -Property Name
    foreach ($scriptFile in $scriptFiles) {
        . $scriptFile.FullName
    }
}

$manifestPath = Join-Path -Path $PSScriptRoot -ChildPath 'MtContainment.psd1'
if (Test-Path -LiteralPath $manifestPath) {
    $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
    Export-ModuleMember -Function $manifest.FunctionsToExport
}
else {
    Export-ModuleMember -Function '*-Mt*'
}
