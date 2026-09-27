function Get-MtCloudEndpoint {
    <#
    .SYNOPSIS
        Returns the login and Graph base URIs for a sovereign cloud.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
        [string]$Cloud = 'Global'
    )

    $map = @{
        Global   = @{ Login = 'https://login.microsoftonline.com'; Graph = 'https://graph.microsoft.com';                  ResourceManager = 'https://management.azure.com' }
        USGov    = @{ Login = 'https://login.microsoftonline.us';  Graph = 'https://graph.microsoft.us';                   ResourceManager = 'https://management.usgovcloudapi.net' }
        USGovDoD = @{ Login = 'https://login.microsoftonline.us';  Graph = 'https://dod-graph.microsoft.us';               ResourceManager = 'https://management.usgovcloudapi.net' }
        China    = @{ Login = 'https://login.chinacloudapi.cn';    Graph = 'https://microsoftgraph.chinacloudapi.cn';      ResourceManager = 'https://management.chinacloudapi.cn' }
    }

    return $map[$Cloud]
}

function ConvertFrom-MtSecureString {
    <#
    .SYNOPSIS
        Materializes a SecureString only for the duration of the call.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [securestring]$Secure
    )

    $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function ConvertTo-MtFormBody {
    <#
    .SYNOPSIS
        Builds an explicitly URL-encoded form body. Never rely on implicit
        hashtable encoding; the ordering and escaping differ across editions.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Fields
    )

    $pairs = New-Object System.Collections.ArrayList
    foreach ($key in ($Fields.Keys | Sort-Object)) {
        $encodedKey = [System.Net.WebUtility]::UrlEncode([string]$key)
        $encodedValue = [System.Net.WebUtility]::UrlEncode([string]$Fields[$key])
        $null = $pairs.Add(('{0}={1}' -f $encodedKey, $encodedValue))
    }

    return ($pairs -join '&')
}

function Test-MtProperty {
    <#
    .SYNOPSIS
        Strict-mode safe property probe for objects returned by ConvertFrom-Json.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $false
    }

    if ($InputObject -is [hashtable]) {
        return $InputObject.ContainsKey($Name)
    }

    # Indexer, not `.Properties.Name -contains`. Under Set-StrictMode -Version
    # Latest, enumerating .Name over an EMPTY property collection throws --
    # and Graph returns {} for empty objects routinely.
    return ($null -ne $InputObject.PSObject.Properties[$Name])
}

function Get-MtProperty {
    <#
    .SYNOPSIS
        Reads a property if present, otherwise returns the supplied default.
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

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $Default
}

function Get-MtDefaultArtifactRoot {
    <#
    .SYNOPSIS
        Picks a writable artifact root.

    .DESCRIPTION
        GetFolderPath('MyDocuments') returns an empty string on Linux, in
        containers, and under some service accounts. Falling through to the
        home directory and then the temp path keeps the module usable from an
        Azure Automation sandbox or an RMM runner as SYSTEM.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidates = @(
        [Environment]::GetFolderPath('MyDocuments')
        [Environment]::GetFolderPath('LocalApplicationData')
        $env:USERPROFILE
        $env:HOME
        [System.IO.Path]::GetTempPath()
    )

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return (Join-Path -Path $candidate -ChildPath 'MtGraph')
        }
    }

    return (Join-Path -Path '.' -ChildPath 'MtGraph')
}

function Get-MtBackoffSeconds {
    <#
    .SYNOPSIS
        Retry-After when the service supplies one, exponential backoff with
        jitter when it does not. Capped so a wedged tenant cannot stall a fleet run.
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory)]
        [int]$Attempt,

        [AllowNull()]
        [string]$RetryAfterHeader,

        [int]$CapSeconds = 60
    )

    $seconds = 0.0

    if (-not [string]::IsNullOrWhiteSpace($RetryAfterHeader)) {
        $parsed = 0
        if ([int]::TryParse($RetryAfterHeader.Trim(), [ref]$parsed)) {
            $seconds = [double]$parsed
        }
    }

    if ($seconds -le 0) {
        $seconds = [math]::Pow(2, [math]::Min($Attempt, 6))
        $seconds = $seconds + ((Get-Random -Minimum 0 -Maximum 1000) / 1000.0)
    }

    return [math]::Min($seconds, [double]$CapSeconds)
}
