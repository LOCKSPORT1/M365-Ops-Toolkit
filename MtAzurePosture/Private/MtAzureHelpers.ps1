function Get-MtAzProperty {
    <#
    .SYNOPSIS
        Strict-mode safe property read.

    .DESCRIPTION
        Uses the PSObject indexer rather than `.Properties.Name -contains`.
        ARM returns {} for empty objects routinely, and under
        Set-StrictMode -Version Latest, enumerating .Name over an empty
        property collection throws.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    if ($InputObject -is [hashtable]) {
        if ($InputObject.ContainsKey($Name)) {
            return $InputObject[$Name]
        }
        return $Default
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $Default
}

function Get-MtAzApiVersion {
    <#
    .SYNOPSIS
        API version per resource provider.

    .DESCRIPTION
        ARM has no tenant-wide default: every provider versions independently
        and a wrong version is a 400, not a soft failure. Pinning them in one
        table is the only maintainable option -- when a provider moves, one
        line changes here rather than a grep across the module.

        These were current as of authoring; verify against the provider docs
        before relying on a new one.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Provider
    )

    $versions = @{
        subscriptions     = '2022-12-01'
        resourceGroups    = '2021-04-01'
        resources         = '2021-04-01'
        roleAssignments   = '2022-04-01'
        roleDefinitions   = '2022-04-01'
        classicAdmins     = '2015-06-01'
        network           = '2023-09-01'
        storage           = '2023-05-01'
        compute           = '2024-07-01'
        policyStates      = '2019-10-01'
        policyAssignments = '2023-04-01'
        insights          = '2021-08-01'
        actionGroups      = '2023-01-01'
        operationalInsights = '2022-10-01'
        recoveryServices  = '2023-04-01'
        locks             = '2016-09-01'
    }

    if ($versions.ContainsKey($Provider)) {
        return $versions[$Provider]
    }

    throw "No API version pinned for provider '$Provider'. Add one to Get-MtAzApiVersion."
}

function Invoke-MtAzRequest {
    <#
    .SYNOPSIS
        ARM GET with permission-aware failure handling.

    .DESCRIPTION
        Returns a result object rather than throwing on 403 or 404. An engineer
        holding Contributor cannot read role assignments in every scope, cannot
        read some Defender for Cloud surfaces, and hits providers that are not
        registered in the subscription at all.

        Treating those as fatal makes the tool useless for the exact role it is
        meant for. Treating them as silent empties is worse -- it produces a
        clean report that means nothing. So each collector records a gap.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$ApiVersion,

        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',

        [switch]$ReadOnlyPost,

        [switch]$Single
    )

    $result = [pscustomobject]@{
        Success = $false
        Denied  = $false
        Items   = @()
        Value   = $null
        Message = ''
    }

    try {
        $splat = @{
            Context    = $Context
            Service    = 'ResourceManager'
            Uri        = $Uri
            ApiVersion = $ApiVersion
            Method     = $Method
            All        = $true
        }

        if ($ReadOnlyPost) {
            $splat['ReadOnlyPost'] = $true
        }

        $response = @(Invoke-MtGraphRequest @splat)
        $result.Success = $true
        $result.Items = $response
        if ($Single -and $response.Count -gt 0) {
            $result.Value = $response[0]
        }
    }
    catch {
        $detail = $_.Exception.Data['MtGraph']
        $statusCode = 0
        if ($null -ne $detail) {
            $statusCode = [int]$detail['statusCode']
        }

        $result.Message = $_.Exception.Message

        if (@(401, 403) -contains $statusCode) {
            $result.Denied = $true
            $result.Message = 'Access denied. The signed-in principal lacks read permission on this scope.'
        }
        elseif ($statusCode -eq 404) {
            $result.Denied = $false
            $result.Message = 'Not found. The resource provider may not be registered in this subscription.'
        }
        else {
            Write-MtLog -Level 'Warning' -Context $Context -Message ('ARM request failed: {0}' -f $_.Exception.Message)
        }
    }

    return $result
}

function Get-MtAdminPortName {
    <#
    .SYNOPSIS
        Human name for a management or database port worth alerting on.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )

    $ports = @{
        22    = 'SSH'
        23    = 'Telnet'
        135   = 'RPC'
        139   = 'NetBIOS'
        445   = 'SMB'
        1433  = 'SQL Server'
        1521  = 'Oracle'
        3306  = 'MySQL'
        3389  = 'RDP'
        5432  = 'PostgreSQL'
        5985  = 'WinRM HTTP'
        5986  = 'WinRM HTTPS'
        6379  = 'Redis'
        9200  = 'Elasticsearch'
        27017 = 'MongoDB'
    }

    if ($ports.ContainsKey($Port)) {
        return $ports[$Port]
    }

    return ''
}

function Test-MtInternetSource {
    <#
    .SYNOPSIS
        True when an NSG rule source prefix means "the whole internet".
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [string]$Prefix
    )

    if ([string]::IsNullOrWhiteSpace($Prefix)) {
        return $false
    }

    $normalized = $Prefix.Trim().ToLowerInvariant()
    return (@('*', 'internet', '0.0.0.0/0', '::/0', 'any') -contains $normalized)
}

function Expand-MtPortRange {
    <#
    .SYNOPSIS
        Expands an NSG port expression into the notable ports it covers.

    .DESCRIPTION
        A rule may say "*", "3389", "0-65535" or "1000-4000". A range that
        happens to swallow RDP is exactly as exposed as a rule naming it, and
        is easier to miss by eye.
    #>
    [CmdletBinding()]
    [OutputType([int[]])]
    param(
        [AllowNull()]
        [string]$PortExpression
    )

    $notable = @(22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 9200, 27017)

    if ([string]::IsNullOrWhiteSpace($PortExpression)) {
        return @()
    }

    $expression = $PortExpression.Trim()

    if ($expression -eq '*') {
        return $notable
    }

    if ($expression -match '^(\d+)\s*-\s*(\d+)$') {
        $low = [int]$Matches[1]
        $high = [int]$Matches[2]
        return @($notable | Where-Object { $_ -ge $low -and $_ -le $high })
    }

    $parsed = 0
    if ([int]::TryParse($expression, [ref]$parsed)) {
        if ($notable -contains $parsed) {
            return @($parsed)
        }
        return @()
    }

    return @()
}

function Get-MtAzResourceGroupName {
    <#
    .SYNOPSIS
        Pulls the resource group out of an ARM resource id.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [string]$ResourceId
    )

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        return ''
    }

    if ($ResourceId -match '/resourceGroups/([^/]+)') {
        return $Matches[1]
    }

    return ''
}

function New-MtAzFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Title,

        [string]$Subscription = '',
        [string]$Resource = '',
        [string]$Detail = '',
        [string]$Recommendation = '',

        [AllowNull()]
        [object]$Evidence = $null
    )

    return [pscustomobject]@{
        Severity       = $Severity
        Category       = $Category
        Title          = $Title
        Subscription   = $Subscription
        Resource       = $Resource
        Detail         = $Detail
        Recommendation = $Recommendation
        Evidence       = $Evidence
    }
}

function Get-MtAzSeverityRank {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$Severity
    )

    $ranks = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }

    if ($ranks.ContainsKey($Severity)) {
        return $ranks[$Severity]
    }

    return 5
}
