@{
    RootModule        = 'MtGraph.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '3d1ec685-b390-4d35-9c92-07cfb136e287'
    Author            = 'Joshua Christy'
    CompanyName       = 'Unaffiliated'
    Copyright         = 'MIT'
    Description       = 'Multi-tenant Microsoft Graph core. Tenant context model, token acquisition (certificate / client secret / device code), resilient request pipeline with paging and throttling, read-only-by-default write gating, and structured run artifacts.'

    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @(
        'New-MtTenantContext'
        'Import-MtTenantConfig'
        'Connect-MtTenant'
        'Disconnect-MtTenant'
        'Get-MtContext'
        'Set-MtWriteMode'
        'Get-MtTenantCapability'
        'Invoke-MtGraphRequest'
        'Invoke-MtForEachTenant'
        'Start-MtRun'
        'Write-MtLog'
        'Complete-MtRun'
        'Get-MtRun'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Graph', 'MultiTenant', 'MSP', 'Entra', 'Intune', 'Automation')
            ProjectUri = 'https://github.com/LOCKSPORT1/O365-Management'
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
