function Get-MtUserAccount {
    <#
    .SYNOPSIS
        Resolves a user and returns the account attributes that matter during
        a compromise investigation.

    .PARAMETER User
        UPN or object id.

    .EXAMPLE
        Get-MtUserAccount -Context $ctx -User 'jdoe@contoso.com'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$User
    )

    $select = 'id,userPrincipalName,displayName,mail,accountEnabled,createdDateTime,lastPasswordChangeDateTime,userType,jobTitle,department,officeLocation,onPremisesSyncEnabled,onPremisesSamAccountName,proxyAddresses,signInSessionsValidFromDateTime'
    $uri = 'users/{0}?$select={1}' -f [uri]::EscapeDataString($User), $select

    $account = Invoke-MtGraphRequest -Context $Context -Uri $uri

    if ($null -eq $account) {
        throw "User '$User' was not found in tenant '$($Context.Name)'."
    }

    return $account
}

function Get-MtUserSignInActivity {
    <#
    .SYNOPSIS
        Returns interactive sign-in log entries for a user over a window.

    .DESCRIPTION
        Requires Entra ID P1 or better. On an unlicensed tenant the endpoint
        returns a licensing error rather than an empty set, so the caller
        should gate on the EntraIdP1 capability.

    .PARAMETER Days
        Lookback window. The service retains 30 days for P1 and P2.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId,

        [ValidateRange(1, 30)]
        [int]$Days = 7,

        [int]$MaxPages = 5
    )

    $cutoff = ConvertTo-MtUtcStamp -Value ([DateTimeOffset]::UtcNow.AddDays(-$Days))
    $filter = "userId eq '{0}' and createdDateTime ge {1}" -f $UserId, $cutoff
    $uri = 'auditLogs/signIns?$filter={0}' -f [uri]::EscapeDataString($filter)

    return @(Invoke-MtGraphRequest -Context $Context -Uri $uri -All -MaxPages $MaxPages)
}

function Get-MtUserAuthMethod {
    <#
    .SYNOPSIS
        Returns the authentication methods registered on the account.

    .DESCRIPTION
        An attacker who registers their own MFA method keeps access through a
        password reset. Comparing this list against the directory audit log is
        how you spot one.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId
    )

    $methods = @(Invoke-MtGraphRequest -Context $Context -Uri ('users/{0}/authentication/methods' -f $UserId) -All)

    foreach ($method in $methods) {
        $type = [string](Get-MtContainmentProperty -InputObject $method -Name '@odata.type' -Default '')
        $friendly = $type -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''

        [pscustomobject]@{
            Id           = [string](Get-MtContainmentProperty -InputObject $method -Name 'id' -Default '')
            Type         = $friendly
            OdataType    = $type
            DisplayName  = [string](Get-MtContainmentProperty -InputObject $method -Name 'displayName' -Default '')
            PhoneNumber  = [string](Get-MtContainmentProperty -InputObject $method -Name 'phoneNumber' -Default '')
            EmailAddress = [string](Get-MtContainmentProperty -InputObject $method -Name 'emailAddress' -Default '')
            DeviceTag    = [string](Get-MtContainmentProperty -InputObject $method -Name 'deviceTag' -Default '')
            CreatedOn    = (Get-MtContainmentProperty -InputObject $method -Name 'createdDateTime' -Default $null)
            Raw          = $method
        }
    }
}

function Get-MtUserInboxRule {
    <#
    .SYNOPSIS
        Returns inbox rules with their forwarding and hiding actions flattened.

    .DESCRIPTION
        Requires MailboxSettings.Read. Mailbox-level SMTP forwarding
        (ForwardingSmtpAddress on Get-Mailbox) is NOT exposed by Graph and must
        be checked separately through Exchange Online PowerShell. This function
        covers rule-based forwarding only, and the report says so.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId,

        [string[]]$TenantDomain = @()
    )

    $rules = @(Invoke-MtGraphRequest -Context $Context -Uri ('users/{0}/mailFolders/inbox/messageRules' -f $UserId) -All)
    $folderCache = @{}

    foreach ($rule in $rules) {
        $actions = Get-MtContainmentProperty -InputObject $rule -Name 'actions' -Default $null
        $recipients = Get-MtRuleRecipient -Actions $actions

        $external = New-Object System.Collections.ArrayList
        foreach ($recipient in $recipients) {
            if (Test-MtExternalRecipient -Address $recipient -TenantDomain $TenantDomain) {
                $null = $external.Add($recipient)
            }
        }

        $moveTo = [string](Get-MtContainmentProperty -InputObject $actions -Name 'moveToFolder' -Default '')
        $moveToName = ''

        # moveToFolder is a folder id, not a name. "Moves mail to RSS Feeds" is
        # the finding; a GUID is not.
        if (-not [string]::IsNullOrWhiteSpace($moveTo)) {
            if ($folderCache.ContainsKey($moveTo)) {
                $moveToName = [string]$folderCache[$moveTo]
            }
            else {
                try {
                    $folder = Invoke-MtGraphRequest -Context $Context -Uri ('users/{0}/mailFolders/{1}?$select=displayName' -f $UserId, $moveTo)
                    $moveToName = [string](Get-MtContainmentProperty -InputObject $folder -Name 'displayName' -Default '')
                }
                catch {
                    Write-MtLog -Level 'Warning' -Context $Context -Message ('Could not resolve mail folder {0}: {1}' -f $moveTo, $_.Exception.Message)
                }
                $folderCache[$moveTo] = $moveToName
            }
        }

        $deletes = [bool](Get-MtContainmentProperty -InputObject $actions -Name 'delete' -Default $false)
        $permanentDelete = [bool](Get-MtContainmentProperty -InputObject $actions -Name 'permanentDelete' -Default $false)
        $markAsRead = [bool](Get-MtContainmentProperty -InputObject $actions -Name 'markAsRead' -Default $false)
        $stopProcessing = [bool](Get-MtContainmentProperty -InputObject $actions -Name 'stopProcessingRules' -Default $false)

        [pscustomobject]@{
            Id                 = [string](Get-MtContainmentProperty -InputObject $rule -Name 'id' -Default '')
            DisplayName        = [string](Get-MtContainmentProperty -InputObject $rule -Name 'displayName' -Default '')
            IsEnabled          = [bool](Get-MtContainmentProperty -InputObject $rule -Name 'isEnabled' -Default $false)
            Sequence           = (Get-MtContainmentProperty -InputObject $rule -Name 'sequence' -Default $null)
            Recipients         = @($recipients)
            ExternalRecipients = @($external)
            MoveToFolder       = $moveTo
            MoveToFolderName   = $moveToName
            Deletes            = $deletes
            PermanentDeletes   = $permanentDelete
            MarksAsRead        = $markAsRead
            StopsProcessing    = $stopProcessing
            Conditions         = (Get-MtContainmentProperty -InputObject $rule -Name 'conditions' -Default $null)
            Raw                = $rule
        }
    }
}

function Get-MtUserOAuthGrant {
    <#
    .SYNOPSIS
        Returns delegated OAuth permission grants made on the user's behalf,
        with the consuming application resolved and each scope risk-rated.

    .DESCRIPTION
        Consent phishing survives a password reset and an MFA re-registration.
        This is the check most containment runbooks forget.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId
    )

    $grants = @(Invoke-MtGraphRequest -Context $Context -Uri ('users/{0}/oauth2PermissionGrants' -f $UserId) -All)
    $appCache = @{}

    foreach ($grant in $grants) {
        $clientId = [string](Get-MtContainmentProperty -InputObject $grant -Name 'clientId' -Default '')
        $appName = 'unknown'
        $publisher = ''
        $verified = $false

        if (-not [string]::IsNullOrWhiteSpace($clientId)) {
            if ($appCache.ContainsKey($clientId)) {
                $servicePrincipal = $appCache[$clientId]
            }
            else {
                $servicePrincipal = $null
                try {
                    $spUri = 'servicePrincipals/{0}?$select=displayName,publisherName,verifiedPublisher,appId,signInAudience' -f $clientId
                    $servicePrincipal = Invoke-MtGraphRequest -Context $Context -Uri $spUri
                }
                catch {
                    Write-MtLog -Level 'Warning' -Context $Context -Message ('Could not resolve service principal {0}: {1}' -f $clientId, $_.Exception.Message)
                }
                $appCache[$clientId] = $servicePrincipal
            }

            if ($null -ne $servicePrincipal) {
                $appName = [string](Get-MtContainmentProperty -InputObject $servicePrincipal -Name 'displayName' -Default 'unknown')
                $publisher = [string](Get-MtContainmentProperty -InputObject $servicePrincipal -Name 'publisherName' -Default '')
                $verifiedPublisher = Get-MtContainmentProperty -InputObject $servicePrincipal -Name 'verifiedPublisher' -Default $null
                $verifiedName = [string](Get-MtContainmentProperty -InputObject $verifiedPublisher -Name 'displayName' -Default '')
                $verified = -not [string]::IsNullOrWhiteSpace($verifiedName)
            }
        }

        $scopeText = [string](Get-MtContainmentProperty -InputObject $grant -Name 'scope' -Default '')
        $scopes = @($scopeText -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        $highestRisk = 'Info'
        $riskyScopes = New-Object System.Collections.ArrayList
        foreach ($scope in $scopes) {
            $risk = Get-MtScopeRisk -Scope $scope
            if ((Get-MtSeverityRank -Severity $risk) -lt (Get-MtSeverityRank -Severity $highestRisk)) {
                $highestRisk = $risk
            }
            if (@('Critical', 'High') -contains $risk) {
                $null = $riskyScopes.Add($scope)
            }
        }

        [pscustomobject]@{
            Id                = [string](Get-MtContainmentProperty -InputObject $grant -Name 'id' -Default '')
            ClientId          = $clientId
            Application       = $appName
            Publisher         = $publisher
            VerifiedPublisher = $verified
            ConsentType       = [string](Get-MtContainmentProperty -InputObject $grant -Name 'consentType' -Default '')
            Scopes            = $scopes
            RiskyScopes       = @($riskyScopes)
            HighestRisk       = $highestRisk
            Raw               = $grant
        }
    }
}

function Get-MtUserPrivilege {
    <#
    .SYNOPSIS
        Returns directory roles, group memberships and owned objects.

    .DESCRIPTION
        Blast radius. A compromised account holding a directory role, or owning
        an app registration, is a tenant incident rather than a mailbox incident.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId
    )

    $memberships = @(Invoke-MtGraphRequest -Context $Context -Uri ('users/{0}/transitiveMemberOf' -f $UserId) -All)
    $owned = @(Invoke-MtGraphRequest -Context $Context -Uri ('users/{0}/ownedObjects' -f $UserId) -All)

    $roles = New-Object System.Collections.ArrayList
    $groups = New-Object System.Collections.ArrayList

    foreach ($membership in $memberships) {
        $type = [string](Get-MtContainmentProperty -InputObject $membership -Name '@odata.type' -Default '')
        $entry = [pscustomobject]@{
            Id          = [string](Get-MtContainmentProperty -InputObject $membership -Name 'id' -Default '')
            DisplayName = [string](Get-MtContainmentProperty -InputObject $membership -Name 'displayName' -Default '')
            Type        = ($type -replace '^#microsoft\.graph\.', '')
        }

        if ($type -eq '#microsoft.graph.directoryRole') {
            $null = $roles.Add($entry)
        }
        else {
            $null = $groups.Add($entry)
        }
    }

    $ownedObjects = New-Object System.Collections.ArrayList
    foreach ($object in $owned) {
        $type = [string](Get-MtContainmentProperty -InputObject $object -Name '@odata.type' -Default '')
        $null = $ownedObjects.Add([pscustomobject]@{
                Id          = [string](Get-MtContainmentProperty -InputObject $object -Name 'id' -Default '')
                DisplayName = [string](Get-MtContainmentProperty -InputObject $object -Name 'displayName' -Default '')
                Type        = ($type -replace '^#microsoft\.graph\.', '')
            })
    }

    return [pscustomobject]@{
        DirectoryRoles = @($roles)
        Groups         = @($groups)
        OwnedObjects   = @($ownedObjects)
    }
}

function Get-MtUserDevice {
    <#
    .SYNOPSIS
        Returns Entra registered devices and, when Intune is licensed, the
        managed device records.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId
    )

    $registered = @(Invoke-MtGraphRequest -Context $Context -Uri ('users/{0}/registeredDevices' -f $UserId) -All)
    $managed = @()

    $capabilities = Get-MtTenantCapability -Context $Context
    if ($capabilities.Intune) {
        try {
            $managed = @(Invoke-MtGraphRequest -Context $Context -Uri ('users/{0}/managedDevices' -f $UserId) -All)
        }
        catch {
            Write-MtLog -Level 'Warning' -Context $Context -Message ('Managed device lookup failed: {0}' -f $_.Exception.Message)
        }
    }

    return [pscustomobject]@{
        Registered = @($registered)
        Managed    = @($managed)
    }
}

function Get-MtUserDirectoryChange {
    <#
    .SYNOPSIS
        Returns directory audit entries that target the user, and entries the
        user initiated, over a window.

    .DESCRIPTION
        Two questions in one call: what was done to this account (MFA method
        added, password reset, role assigned), and what did this account do to
        the tenant while it was in someone else's hands.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId,

        [ValidateRange(1, 30)]
        [int]$Days = 7,

        [int]$MaxPages = 5
    )

    $cutoff = ConvertTo-MtUtcStamp -Value ([DateTimeOffset]::UtcNow.AddDays(-$Days))

    $targetFilter = "targetResources/any(t: t/id eq '{0}') and activityDateTime ge {1}" -f $UserId, $cutoff
    $initiatedFilter = "initiatedBy/user/id eq '{0}' and activityDateTime ge {1}" -f $UserId, $cutoff

    $targeting = @()
    $initiated = @()

    try {
        $targeting = @(Invoke-MtGraphRequest -Context $Context -Uri ('auditLogs/directoryAudits?$filter={0}' -f [uri]::EscapeDataString($targetFilter)) -All -MaxPages $MaxPages)
    }
    catch {
        Write-MtLog -Level 'Warning' -Context $Context -Message ('Directory audit lookup (target) failed: {0}' -f $_.Exception.Message)
    }

    try {
        $initiated = @(Invoke-MtGraphRequest -Context $Context -Uri ('auditLogs/directoryAudits?$filter={0}' -f [uri]::EscapeDataString($initiatedFilter)) -All -MaxPages $MaxPages)
    }
    catch {
        Write-MtLog -Level 'Warning' -Context $Context -Message ('Directory audit lookup (initiated) failed: {0}' -f $_.Exception.Message)
    }

    return [pscustomobject]@{
        TargetingUser = @($targeting)
        InitiatedByUser = @($initiated)
    }
}

function Get-MtUserRisk {
    <#
    .SYNOPSIS
        Returns Identity Protection risk state and recent detections.

    .DESCRIPTION
        Requires Entra ID P2. Returns an empty result rather than throwing when
        the tenant is not licensed, so the investigation orchestrator can call
        it unconditionally.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId,

        [ValidateRange(1, 90)]
        [int]$Days = 7
    )

    $result = [pscustomobject]@{
        Licensed   = $false
        RiskyUser  = $null
        Detections = @()
    }

    $capabilities = Get-MtTenantCapability -Context $Context
    if (-not $capabilities.EntraIdP2) {
        return $result
    }

    $result.Licensed = $true

    try {
        $result.RiskyUser = Invoke-MtGraphRequest -Context $Context -Uri ('identityProtection/riskyUsers/{0}' -f $UserId)
    }
    catch {
        Write-MtLog -Level 'Warning' -Context $Context -Message ('Risky user lookup failed: {0}' -f $_.Exception.Message)
    }

    try {
        $cutoff = ConvertTo-MtUtcStamp -Value ([DateTimeOffset]::UtcNow.AddDays(-$Days))
        $filter = "userId eq '{0}' and detectedDateTime ge {1}" -f $UserId, $cutoff
        $result.Detections = @(Invoke-MtGraphRequest -Context $Context -Uri ('identityProtection/riskDetections?$filter={0}' -f [uri]::EscapeDataString($filter)) -All -MaxPages 3)
    }
    catch {
        Write-MtLog -Level 'Warning' -Context $Context -Message ('Risk detection lookup failed: {0}' -f $_.Exception.Message)
    }

    return $result
}
