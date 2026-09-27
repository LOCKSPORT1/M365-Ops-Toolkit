function Get-MtTenantCapability {
    <#
    .SYNOPSIS
        Discovers what a tenant is actually licensed for, from subscribedSkus.

    .DESCRIPTION
        Every tool built on this module should branch on capability rather than
        assume. Client A is E3 with no Defender; client B is E5 with Sentinel.
        Calling a Purview endpoint on a tenant with no Purview plan returns a
        confusing 403, not a helpful "not licensed".

        Results are cached on the context. Use -Refresh after a licensing change.

    .EXAMPLE
        $caps = Get-MtTenantCapability -Context $ctx
        if ($caps.EntraIdP2) { ... risky sign-in queries ... }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Context,

        [switch]$Refresh
    )

    process {
        if ($Context.Capabilities.Count -gt 0 -and -not $Refresh) {
            return [pscustomobject]$Context.Capabilities
        }

        $skus = @(Invoke-MtGraphRequest -Context $Context -Uri 'subscribedSkus' -All)

        $plans = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
        $skuParts = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($sku in $skus) {
            $partNumber = [string](Get-MtProperty -InputObject $sku -Name 'skuPartNumber' -Default '')
            if (-not [string]::IsNullOrWhiteSpace($partNumber)) {
                $null = $skuParts.Add($partNumber)
            }

            foreach ($plan in @(Get-MtProperty -InputObject $sku -Name 'servicePlans' -Default @())) {
                $status = [string](Get-MtProperty -InputObject $plan -Name 'provisioningStatus' -Default '')
                if (@('Success', 'PendingInput', 'PendingActivation', 'PendingProvisioning') -contains $status) {
                    $planName = [string](Get-MtProperty -InputObject $plan -Name 'servicePlanName' -Default '')
                    if (-not [string]::IsNullOrWhiteSpace($planName)) {
                        $null = $plans.Add($planName)
                    }
                }
            }
        }

        $capabilities = [ordered]@{
            EntraIdP1                = ($plans.Contains('AAD_PREMIUM'))
            EntraIdP2                = ($plans.Contains('AAD_PREMIUM_P2'))
            Intune                   = ($plans.Contains('INTUNE_A') -or $plans.Contains('INTUNE_A_D') -or $plans.Contains('INTUNE_EDU'))
            ExchangeOnline           = ($plans.Contains('EXCHANGE_S_ENTERPRISE') -or $plans.Contains('EXCHANGE_S_STANDARD'))
            SharePointOnline         = ($plans.Contains('SHAREPOINTENTERPRISE') -or $plans.Contains('SHAREPOINTSTANDARD'))
            Teams                    = ($plans.Contains('TEAMS1') -or $plans.Contains('TEAMS_ESSENTIALS'))
            DefenderForOfficeP1      = ($plans.Contains('ATP_ENTERPRISE'))
            DefenderForOfficeP2      = ($plans.Contains('THREAT_INTELLIGENCE'))
            DefenderForEndpoint      = ($plans.Contains('WINDEFATP') -or $plans.Contains('MDATP_XPLAT'))
            DefenderForIdentity      = ($plans.Contains('ATA'))
            DefenderForCloudApps     = ($plans.Contains('ADALLOM_S_STANDALONE') -or $plans.Contains('ADALLOM_S_O365'))
            PurviewAdvancedAudit     = ($plans.Contains('M365_ADVANCED_AUDITING'))
            PurviewEDiscoveryPremium = ($plans.Contains('EQUIVIO_ANALYTICS'))
            PurviewInfoProtection    = ($plans.Contains('RMS_S_ENTERPRISE') -or $plans.Contains('RMS_S_PREMIUM'))
            PurviewInsiderRisk       = ($plans.Contains('INSIDER_RISK') -or $plans.Contains('INSIDER_RISK_MANAGEMENT'))
            CustomerLockbox          = ($plans.Contains('LOCKBOX_ENTERPRISE'))
            PowerAutomate            = ($plans.Contains('FLOW_O365_P2') -or $plans.Contains('FLOW_O365_P3'))
            E5Suite                  = ($skuParts.Contains('SPE_E5') -or $skuParts.Contains('ENTERPRISEPREMIUM') -or $skuParts.Contains('SPE_E5_NOPSTNCONF'))
            SkuPartNumbers           = (@($skuParts) | Sort-Object)
            DiscoveredOn             = [DateTimeOffset]::UtcNow
        }

        $Context.Capabilities = $capabilities

        $enabled = @($capabilities.Keys | Where-Object {
                $value = $capabilities[$_]
                ($value -is [bool]) -and $value
            })

        Write-MtLog -Context $Context -Message ('Capability discovery: {0} SKU(s), {1} capability flag(s) enabled.' -f $skuParts.Count, $enabled.Count) -Data @{
            skus     = @($skuParts)
            enabled  = $enabled
        }

        return [pscustomobject]$capabilities
    }
}
