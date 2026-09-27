function Get-MtAuthMethodEndpoint {
    <#
    .SYNOPSIS
        Maps an authentication method type to its Graph collection segment.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Type
    )

    $map = @{
        phone                   = 'phoneMethods'
        microsoftAuthenticator  = 'microsoftAuthenticatorMethods'
        email                   = 'emailMethods'
        fido2                   = 'fido2Methods'
        softwareOath            = 'softwareOathMethods'
        windowsHelloForBusiness = 'windowsHelloForBusinessMethods'
        temporaryAccessPass     = 'temporaryAccessPassMethods'
    }

    if ($map.ContainsKey($Type)) {
        return $map[$Type]
    }

    return ''
}

function Test-MtSimulated {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object]$Result
    )

    return [bool](Get-MtContainmentProperty -InputObject $Result -Name 'Simulated' -Default $false)
}

function New-MtActionResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Action,

        [string]$Target = '',

        [bool]$Success = $true,

        [bool]$Simulated = $false,

        [string]$Message = ''
    )

    return [pscustomobject]@{
        PSTypeName = 'MtContainment.ActionResult'
        Action     = $Action
        Target     = $Target
        Success    = $Success
        Simulated  = $Simulated
        Message    = $Message
        OccurredOn = [DateTimeOffset]::UtcNow
    }
}

function Disable-MtUserAccount {
    <#
    .SYNOPSIS
        Blocks sign-in by setting accountEnabled to false.

    .DESCRIPTION
        Fastest block on new authentication. Does not kill sessions already
        issued -- Revoke-MtUserSession does that, and must run after any
        password reset.

        On a hybrid account this is overwritten at the next Entra Connect sync
        unless the on-premises account is disabled too. The result message says
        so when the account is synced.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId,

        [AllowNull()]
        [object]$Account = $null
    )

    $result = Invoke-MtGraphRequest -Context $Context -Method 'PATCH' -Uri ('users/{0}' -f $UserId) -Body @{ accountEnabled = $false }
    $simulated = Test-MtSimulated -Result $result

    $message = 'Sign-in blocked.'
    if ([bool](Get-MtContainmentProperty -InputObject $Account -Name 'onPremisesSyncEnabled' -Default $false)) {
        $message = 'Sign-in blocked in Entra. This account is synced from on-premises AD: disable the AD account as well or the next sync will re-enable it.'
    }

    return New-MtActionResult -Action 'DisableAccount' -Target $UserId -Simulated $simulated -Message $message
}

function Reset-MtUserPassword {
    <#
    .SYNOPSIS
        Sets a new random password and forces a change at next sign-in.

    .DESCRIPTION
        The generated password is returned on the result object and is NEVER
        written to the run log -- the underlying request is sent with
        -RedactBody for exactly that reason. Hand it over out of band and do not
        paste it into the ticket.

        Does nothing useful on its own: a password reset without a session
        revocation leaves existing refresh tokens valid for up to 90 days.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId,

        [ValidateRange(12, 128)]
        [int]$Length = 20,

        [switch]$NoForceChange
    )

    $password = New-MtRandomPassword -Length $Length

    $body = @{
        passwordProfile = @{
            password                      = $password
            forceChangePasswordNextSignIn = (-not $NoForceChange.IsPresent)
        }
    }

    $result = Invoke-MtGraphRequest -Context $Context -Method 'PATCH' -Uri ('users/{0}' -f $UserId) -Body $body -RedactBody
    $simulated = Test-MtSimulated -Result $result

    $actionResult = New-MtActionResult -Action 'ResetPassword' -Target $UserId -Simulated $simulated -Message 'Password reset. Deliver out of band; it is not in the run log.'
    Add-Member -InputObject $actionResult -MemberType NoteProperty -Name 'Password' -Value $password -Force

    return $actionResult
}

function Remove-MtUserAuthMethod {
    <#
    .SYNOPSIS
        Removes a registered authentication method.

    .DESCRIPTION
        Run this before the password reset. An attacker-registered method lets
        them complete self-service password reset and walk straight back in.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$MethodId,

        [Parameter(Mandatory, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$MethodType
    )

    $segment = Get-MtAuthMethodEndpoint -Type $MethodType

    if ([string]::IsNullOrWhiteSpace($segment)) {
        return New-MtActionResult -Action 'RemoveAuthMethod' -Target $MethodId -Success $false `
            -Message ("Method type '{0}' cannot be removed through Graph. The password method in particular has no delete operation." -f $MethodType)
    }

    $uri = 'users/{0}/authentication/{1}/{2}' -f $UserId, $segment, $MethodId
    $result = Invoke-MtGraphRequest -Context $Context -Method 'DELETE' -Uri $uri
    $simulated = Test-MtSimulated -Result $result

    return New-MtActionResult -Action 'RemoveAuthMethod' -Target ('{0} ({1})' -f $MethodId, $MethodType) -Simulated $simulated -Message 'Authentication method removed.'
}

function Revoke-MtUserSession {
    <#
    .SYNOPSIS
        Invalidates refresh tokens and session cookies.

    .DESCRIPTION
        Must run LAST among the identity actions. Any token minted between the
        revocation and a subsequent password change survives, so revoking first
        and resetting second leaves a window open.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId
    )

    $result = Invoke-MtGraphRequest -Context $Context -Method 'POST' -Uri ('users/{0}/revokeSignInSessions' -f $UserId)
    $simulated = Test-MtSimulated -Result $result

    return New-MtActionResult -Action 'RevokeSessions' -Target $UserId -Simulated $simulated -Message 'Refresh tokens and session cookies invalidated. Propagation is not instant; re-check sign-in logs.'
}

function Remove-MtUserInboxRule {
    <#
    .SYNOPSIS
        Deletes an inbox rule.

    .DESCRIPTION
        Capture the rule definition in the investigation artifact first. Once
        deleted it is gone, and the rule is evidence.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$RuleId,

        [string]$RuleName = ''
    )

    $uri = 'users/{0}/mailFolders/inbox/messageRules/{1}' -f $UserId, $RuleId
    $result = Invoke-MtGraphRequest -Context $Context -Method 'DELETE' -Uri $uri
    $simulated = Test-MtSimulated -Result $result

    $target = $RuleId
    if (-not [string]::IsNullOrWhiteSpace($RuleName)) {
        $target = '{0} ({1})' -f $RuleName, $RuleId
    }

    return New-MtActionResult -Action 'RemoveInboxRule' -Target $target -Simulated $simulated -Message 'Inbox rule deleted. Definition retained in the investigation artifact.'
}

function Revoke-MtUserOAuthGrant {
    <#
    .SYNOPSIS
        Deletes a delegated OAuth permission grant.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$GrantId,

        [string]$ApplicationName = ''
    )

    $result = Invoke-MtGraphRequest -Context $Context -Method 'DELETE' -Uri ('oauth2PermissionGrants/{0}' -f $GrantId)
    $simulated = Test-MtSimulated -Result $result

    $target = $GrantId
    if (-not [string]::IsNullOrWhiteSpace($ApplicationName)) {
        $target = '{0} ({1})' -f $ApplicationName, $GrantId
    }

    return New-MtActionResult -Action 'RevokeOAuthGrant' -Target $target -Simulated $simulated -Message 'Delegated consent revoked for this user. Other users may still have consented to the same application.'
}

function Confirm-MtUserCompromised {
    <#
    .SYNOPSIS
        Marks the user compromised in Identity Protection.

    .DESCRIPTION
        Requires Entra ID P2. Feeds the signal back into risk-based policies
        rather than leaving the risk state stale after containment.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$UserId
    )

    $capabilities = Get-MtTenantCapability -Context $Context
    if (-not $capabilities.EntraIdP2) {
        return New-MtActionResult -Action 'ConfirmCompromised' -Target $UserId -Success $false `
            -Message 'Skipped: Identity Protection requires Entra ID P2 and this tenant is not licensed for it.'
    }

    $result = Invoke-MtGraphRequest -Context $Context -Method 'POST' -Uri 'identityProtection/riskyUsers/confirmCompromised' -Body @{ userIds = @($UserId) }
    $simulated = Test-MtSimulated -Result $result

    return New-MtActionResult -Action 'ConfirmCompromised' -Target $UserId -Simulated $simulated -Message 'User confirmed compromised in Identity Protection.'
}

function Invoke-MtAccountContainment {
    <#
    .SYNOPSIS
        Runs containment against an investigated account, in the correct order.

    .DESCRIPTION
        Takes the investigation object rather than a username, so every action
        is driven by evidence already collected and captured in the artifact.

        The sequence is not arbitrary:

          1. Disable the account      -- fastest block on new authentication
          2. Remove hostile MFA       -- before the reset, or the attacker can
                                         self-service the password back
          3. Reset the password       -- optional; the credential itself
          4. Revoke sessions          -- LAST, so nothing issued mid-sequence survives
          5. Remove inbox rules       -- persistence and evidence destruction
          6. Revoke OAuth grants      -- the persistence that survives 1 through 4
          7. Confirm compromised      -- feed the signal back to risk policies

        Against a read-only context every step is simulated and logged, so this
        doubles as a dry run you can show someone before arming it.

    .PARAMETER Scope
        Which actions to run. 'Standard' is steps 1, 2, 4, 5 and 6 -- everything
        except the password reset and the Identity Protection call.

    .EXAMPLE
        # Dry run: context is read-only by default
        $investigation = Get-MtUserInvestigation -Context $ctx -User 'jdoe@contoso.com'
        Invoke-MtAccountContainment -Context $ctx -Investigation $investigation -Scope Standard

    .EXAMPLE
        Set-MtWriteMode -Context $ctx -AllowWrites
        Invoke-MtAccountContainment -Context $ctx -Investigation $investigation -Scope Full -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Investigation,

        [ValidateSet('Standard', 'Full', 'Custom')]
        [string]$Scope = 'Standard',

        [switch]$DisableAccount,
        [switch]$RemoveRecentAuthMethods,
        [switch]$ResetPassword,
        [switch]$RevokeSessions,
        [switch]$RemoveHostileInboxRules,
        [switch]$RevokeRiskyGrants,
        [switch]$ConfirmCompromised
    )

    process {
        $userId = [string]$Investigation.UserId
        $upn = [string]$Investigation.UserPrincipalName

        if ($Scope -eq 'Standard') {
            $DisableAccount = $true
            $RemoveRecentAuthMethods = $true
            $RevokeSessions = $true
            $RemoveHostileInboxRules = $true
            $RevokeRiskyGrants = $true
        }
        elseif ($Scope -eq 'Full') {
            $DisableAccount = $true
            $RemoveRecentAuthMethods = $true
            $ResetPassword = $true
            $RevokeSessions = $true
            $RemoveHostileInboxRules = $true
            $RevokeRiskyGrants = $true
            $ConfirmCompromised = $true
        }

        $mode = 'ARMED'
        if ($Context.WhatIfMode) {
            $mode = 'read-only (simulation)'
        }

        Write-MtLog -Level 'Warning' -Context $Context -Message ('Containment starting for {0} -- scope {1}, mode {2}.' -f $upn, $Scope, $mode)

        $actions = New-Object System.Collections.ArrayList

        # 1. Block new authentication.
        if ($DisableAccount) {
            $null = $actions.Add((Disable-MtUserAccount -Context $Context -UserId $userId -Account $Investigation.Account -Confirm:$false))
        }

        # 2. Strip attacker-registered MFA before touching the password.
        if ($RemoveRecentAuthMethods) {
            $windowStart = ([DateTimeOffset]$Investigation.CollectedOn).AddDays(-$Investigation.LookbackDays)
            $recent = @($Investigation.AuthMethods | Where-Object {
                    $null -ne $_.CreatedOn -and ([DateTimeOffset]$_.CreatedOn) -ge $windowStart
                })

            if ($recent.Count -eq 0) {
                $null = $actions.Add((New-MtActionResult -Action 'RemoveAuthMethod' -Target '(none)' -Message 'No authentication methods were registered inside the lookback window.'))
            }

            foreach ($method in $recent) {
                $null = $actions.Add((Remove-MtUserAuthMethod -Context $Context -UserId $userId -MethodId $method.Id -MethodType $method.Type -Confirm:$false))
            }
        }

        # 3. The credential itself.
        if ($ResetPassword) {
            $null = $actions.Add((Reset-MtUserPassword -Context $Context -UserId $userId -Confirm:$false))
        }

        # 4. Kill everything already issued. Order matters: see the description.
        if ($RevokeSessions) {
            $null = $actions.Add((Revoke-MtUserSession -Context $Context -UserId $userId -Confirm:$false))
        }

        # 5. Mail persistence.
        if ($RemoveHostileInboxRules) {
            $hostile = @($Investigation.InboxRules | Where-Object {
                    @($_.ExternalRecipients).Count -gt 0 -or $_.PermanentDeletes -or $_.Deletes
                })

            if ($hostile.Count -eq 0) {
                $null = $actions.Add((New-MtActionResult -Action 'RemoveInboxRule' -Target '(none)' -Message 'No rules with external forwarding or deletion actions were found.'))
            }

            foreach ($rule in $hostile) {
                $null = $actions.Add((Remove-MtUserInboxRule -Context $Context -UserId $userId -RuleId $rule.Id -RuleName $rule.DisplayName -Confirm:$false))
            }
        }

        # 6. The persistence that survives every step above.
        if ($RevokeRiskyGrants) {
            $risky = @($Investigation.OAuthGrants | Where-Object { @($_.RiskyScopes).Count -gt 0 })

            if ($risky.Count -eq 0) {
                $null = $actions.Add((New-MtActionResult -Action 'RevokeOAuthGrant' -Target '(none)' -Message 'No delegated grants with sensitive scopes were found.'))
            }

            foreach ($grant in $risky) {
                $null = $actions.Add((Revoke-MtUserOAuthGrant -Context $Context -GrantId $grant.Id -ApplicationName $grant.Application -Confirm:$false))
            }
        }

        # 7. Close the loop with Identity Protection.
        if ($ConfirmCompromised) {
            $null = $actions.Add((Confirm-MtUserCompromised -Context $Context -UserId $userId -Confirm:$false))
        }

        $applied = @($actions | Where-Object { $_.Success -and -not $_.Simulated -and $_.Target -ne '(none)' }).Count
        $simulated = @($actions | Where-Object { $_.Simulated }).Count

        Write-MtLog -Level 'Warning' -Context $Context -Message ('Containment finished for {0}: {1} applied, {2} simulated.' -f $upn, $applied, $simulated)

        return [pscustomobject]@{
            PSTypeName        = 'MtContainment.Result'
            Tenant            = $Context.Name
            UserPrincipalName = $upn
            UserId            = $userId
            Scope             = $Scope
            Mode              = $mode
            AppliedCount      = $applied
            SimulatedCount    = $simulated
            Actions           = @($actions)
            CompletedOn       = [DateTimeOffset]::UtcNow
        }
    }
}
