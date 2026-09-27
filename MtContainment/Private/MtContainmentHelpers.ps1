function Get-MtContainmentProperty {
    <#
    .SYNOPSIS
        Strict-mode safe property read for objects returned by Graph.

    .DESCRIPTION
        MtGraph exports a private helper of the same shape, but private
        functions do not cross module boundaries. Duplicated deliberately
        rather than widening MtGraph's public surface for a two-line helper.
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

    # Indexer, not `.Properties.Name -contains`. Graph returns {} for empty
    # objects (verifiedPublisher, location, status), and under
    # Set-StrictMode -Version Latest, member enumeration over an EMPTY property
    # collection throws "The property 'Name' cannot be found on this object."
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $Default
}

function Get-MtTenantDomain {
    <#
    .SYNOPSIS
        Returns the tenant's accepted domains, used to classify a mail
        recipient as internal or external.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    $domains = @(Invoke-MtGraphRequest -Context $Context -Uri 'domains?$select=id,isVerified' -All)

    $names = New-Object System.Collections.ArrayList
    foreach ($domain in $domains) {
        $id = [string](Get-MtContainmentProperty -InputObject $domain -Name 'id' -Default '')
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $null = $names.Add($id.ToLowerInvariant())
        }
    }

    return @($names)
}

function Test-MtExternalRecipient {
    <#
    .SYNOPSIS
        True when a mail recipient sits outside every tenant domain.

    .DESCRIPTION
        The core signal in business email compromise: a rule that forwards or
        redirects outside the organization. Subdomains of an accepted domain
        count as internal.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [string]$Address,

        [string[]]$TenantDomain = @()
    )

    if ([string]::IsNullOrWhiteSpace($Address)) {
        return $false
    }

    $at = $Address.LastIndexOf('@')
    if ($at -lt 0) {
        return $false
    }

    $domain = $Address.Substring($at + 1).Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($domain)) {
        return $false
    }

    foreach ($accepted in $TenantDomain) {
        if ($domain -eq $accepted) {
            return $false
        }

        if ($domain.EndsWith('.' + $accepted)) {
            return $false
        }
    }

    return $true
}

function Get-MtRuleRecipient {
    <#
    .SYNOPSIS
        Flattens the recipient collections on an inbox rule action into
        plain SMTP addresses.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowNull()]
        [object]$Actions
    )

    $addresses = New-Object System.Collections.ArrayList

    foreach ($field in @('forwardTo', 'redirectTo', 'forwardAsAttachmentTo')) {
        foreach ($recipient in @(Get-MtContainmentProperty -InputObject $Actions -Name $field -Default @())) {
            $emailAddress = Get-MtContainmentProperty -InputObject $recipient -Name 'emailAddress' -Default $null
            $address = [string](Get-MtContainmentProperty -InputObject $emailAddress -Name 'address' -Default '')
            if (-not [string]::IsNullOrWhiteSpace($address)) {
                $null = $addresses.Add($address)
            }
        }
    }

    return @($addresses)
}

function Get-MtScopeRisk {
    <#
    .SYNOPSIS
        Severity for a delegated OAuth scope granted on the user's behalf.

    .DESCRIPTION
        Consent phishing is the persistence mechanism that survives a password
        reset. Mail and file scopes are what an attacker actually wants;
        offline_access is what makes the grant durable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Scope
    )

    $critical = @(
        'Mail.ReadWrite', 'Mail.Send', 'Mail.ReadWrite.All', 'Mail.Send.All'
        'MailboxSettings.ReadWrite', 'Files.ReadWrite.All', 'Directory.ReadWrite.All'
        'User.ReadWrite.All', 'Application.ReadWrite.All', 'RoleManagement.ReadWrite.Directory'
    )

    $high = @(
        'Mail.Read', 'Mail.Read.All', 'MailboxSettings.Read', 'Files.Read.All'
        'Sites.ReadWrite.All', 'Sites.Read.All', 'Contacts.ReadWrite', 'Notes.ReadWrite.All'
        'Directory.Read.All', 'Chat.ReadWrite', 'ChannelMessage.Read.All'
    )

    $trimmed = $Scope.Trim()

    if ($critical -contains $trimmed) {
        return 'Critical'
    }

    if ($high -contains $trimmed) {
        return 'High'
    }

    if ($trimmed -eq 'offline_access') {
        return 'Medium'
    }

    return 'Info'
}

function New-MtRandomPassword {
    <#
    .SYNOPSIS
        Generates a password using a cryptographic RNG.

    .DESCRIPTION
        Get-Random is not cryptographically secure and must never be used to
        mint a credential. Characters that are ambiguous when a password is
        read aloud over the phone during an incident are excluded.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [ValidateRange(12, 128)]
        [int]$Length = 20
    )

    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^*-_=+'
    $bytes = New-Object 'byte[]' $Length

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }

    $builder = New-Object System.Text.StringBuilder
    foreach ($byte in $bytes) {
        $null = $builder.Append($alphabet[$byte % $alphabet.Length])
    }

    return $builder.ToString()
}

function ConvertTo-MtUtcStamp {
    <#
    .SYNOPSIS
        Formats a cutoff for a Graph $filter clause.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [DateTimeOffset]$Value
    )

    return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function New-MtFinding {
    <#
    .SYNOPSIS
        Builds one prioritized finding.
    #>
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

        [string]$Detail = '',

        [string]$Recommendation = '',

        [AllowNull()]
        [object]$Evidence = $null
    )

    $finding = [pscustomobject]@{
        Severity       = $Severity
        Category       = $Category
        Title          = $Title
        Detail         = $Detail
        Recommendation = $Recommendation
        Evidence       = $Evidence
    }

    return $finding
}

function Get-MtSeverityRank {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$Severity
    )

    $ranks = @{
        Critical = 0
        High     = 1
        Medium   = 2
        Low      = 3
        Info     = 4
    }

    if ($ranks.ContainsKey($Severity)) {
        return $ranks[$Severity]
    }

    return 5
}

function Format-MtTimestamp {
    <#
    .SYNOPSIS
        Renders a timestamp as invariant UTC.

    .DESCRIPTION
        ConvertFrom-Json turns ISO strings into DateTime, and the default
        ToString() then uses the running account's culture. "03/01/2026" in an
        incident report is March 1 or January 3 depending on who reads it.
        Everything in a report goes out as yyyy-MM-dd HH:mm:ss UTC.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [DateTime]) {
        return ([DateTime]$Value).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Value -is [DateTimeOffset]) {
        return ([DateTimeOffset]$Value).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return ''
    }

    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($text, [ref]$parsed)) {
        return $parsed.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    return $text
}
