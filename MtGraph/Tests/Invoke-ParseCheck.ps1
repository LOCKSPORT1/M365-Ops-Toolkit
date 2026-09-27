$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$failed = $false
Get-ChildItem -Path $root -Recurse -Include '*.ps1','*.psm1','*.psd1' | Sort-Object FullName | ForEach-Object {
    $tokens = $null; $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        $script:failed = $true
        Write-Host "FAIL $($_.FullName)" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host ("  line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) }
    } else {
        Write-Host "ok   $($_.Name)"
    }
}
if ($failed) { exit 1 }
