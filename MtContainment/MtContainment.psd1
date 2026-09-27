@{
    RootModule        = 'MtContainment.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'c47a9f10-2d6b-4a55-9e31-6b0d8f4a1c72'
    Author            = 'Joshua Christy'
    CompanyName       = 'Unaffiliated'
    Copyright         = 'MIT'
    Description       = 'Account compromise investigation and containment for Microsoft 365, built on MtGraph. Read-only evidence collection, prioritized findings, and gated containment actions that document themselves.'

    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules   = @('MtGraph')

    FunctionsToExport = @(
        # Evidence collection (always read-only)
        'Get-MtUserAccount'
        'Get-MtUserSignInActivity'
        'Get-MtUserAuthMethod'
        'Get-MtUserInboxRule'
        'Get-MtUserOAuthGrant'
        'Get-MtUserPrivilege'
        'Get-MtUserDevice'
        'Get-MtUserDirectoryChange'
        'Get-MtUserRisk'
        'Get-MtUserInvestigation'

        # Triage
        'Get-MtInvestigationFinding'
        'Export-MtInvestigationReport'

        # Containment (gated by the context write mode)
        'Invoke-MtAccountContainment'
        'Disable-MtUserAccount'
        'Revoke-MtUserSession'
        'Reset-MtUserPassword'
        'Remove-MtUserInboxRule'
        'Revoke-MtUserOAuthGrant'
        'Remove-MtUserAuthMethod'
        'Confirm-MtUserCompromised'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Microsoft365', 'Graph', 'IncidentResponse', 'BEC', 'Containment', 'Entra', 'Security')
            ProjectUri = 'https://github.com/LOCKSPORT1/O365-Management'
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
