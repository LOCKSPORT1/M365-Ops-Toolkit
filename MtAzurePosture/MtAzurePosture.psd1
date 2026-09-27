@{
    RootModule        = 'MtAzurePosture.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'e93b27d4-8c15-4f62-ab70-3d5e1a9c4482'
    Author            = 'Joshua Christy'
    CompanyName       = 'Unaffiliated'
    Copyright         = 'MIT'
    Description       = 'Read-only Azure governance, network, storage, resilience and monitoring sweep across subscriptions. Built on MtGraph.'

    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules   = @('MtGraph')

    FunctionsToExport = @(
        'Get-MtAzureSubscription'
        'Get-MtAzureRoleAssignment'
        'Get-MtAzureNetworkExposure'
        'Get-MtAzureStorageAccount'
        'Get-MtAzureComputeHygiene'
        'Get-MtAzurePolicyState'
        'Get-MtAzureMonitoring'
        'Get-MtAzurePosture'
        'Get-MtAzureFinding'
        'Export-MtAzureReport'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Azure', 'Governance', 'Posture', 'RBAC', 'NSG', 'AZ104', 'Security')
            ProjectUri = 'https://github.com/LOCKSPORT1/O365-Management'
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
