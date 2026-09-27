function Get-MtUserInvestigation {
    <#
    .SYNOPSIS
        Collects every evidence source for one account in a single read-only pass.

    .DESCRIPTION
        This is the thirty-second version of the hour an L2 spends clicking
        through portals. Nothing here mutates anything, so it is safe to run on
        a hunch and safe to hand to a junior technician.

        Each collector is wrapped independently. A tenant missing Entra ID P1,
        a mailbox that has no inbox, or a permission the app registration was
        never granted degrades that one section rather than failing the sweep.
        Collection errors are recorded on the result so the report can say what
        was not checked -- a gap you know about is evidence; a gap you do not is
        a false all-clear.

    .PARAMETER Days
        Lookback window for sign-ins, audit entries and risk detections.

    .EXAMPLE
        $investigation = Get-MtUserInvestigation -Context $ctx -User 'jdoe@contoso.com' -Days 7
        Get-MtInvestigationFinding -Investigation $investigation | Format-Table Severity, Title

    .EXAMPLE
        $investigation | Export-MtInvestigationReport -Path .\INC-4471
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [ValidateRange(1, 30)]
        [int]$Days = 7
    )

    process {
        $started = [DateTimeOffset]::UtcNow
        Write-MtLog -Context $Context -Message ('Starting investigation of {0} over {1} day(s).' -f $User, $Days)

        $account = Get-MtUserAccount -Context $Context -User $User
        $userId = [string](Get-MtContainmentProperty -InputObject $account -Name 'id' -Default '')
        $upn = [string](Get-MtContainmentProperty -InputObject $account -Name 'userPrincipalName' -Default $User)

        $capabilities = Get-MtTenantCapability -Context $Context

        $investigation = [pscustomobject]@{
            PSTypeName        = 'MtContainment.Investigation'
            Tenant            = $Context.Name
            TenantId          = $Context.TenantId
            UserId            = $userId
            UserPrincipalName = $upn
            Account           = $account
            LookbackDays      = $Days
            CollectedOn       = $started
            TenantDomains     = @()
            SignIns           = @()
            AuthMethods       = @()
            InboxRules        = @()
            OAuthGrants       = @()
            Privilege         = $null
            Devices           = $null
            DirectoryChanges  = $null
            Risk              = $null
            Capabilities      = $capabilities
            NotChecked        = (New-Object System.Collections.ArrayList)
            Errors            = (New-Object System.Collections.ArrayList)
        }

        $collectors = @(
            @{ Name = 'TenantDomains'; Gate = $true; Action = { Get-MtTenantDomain -Context $Context } }
            @{ Name = 'SignIns'; Gate = $capabilities.EntraIdP1; GateReason = 'Sign-in logs require Entra ID P1 or better.'; Action = { Get-MtUserSignInActivity -Context $Context -UserId $userId -Days $Days } }
            @{ Name = 'AuthMethods'; Gate = $true; Action = { Get-MtUserAuthMethod -Context $Context -UserId $userId } }
            @{ Name = 'OAuthGrants'; Gate = $true; Action = { Get-MtUserOAuthGrant -Context $Context -UserId $userId } }
            @{ Name = 'Privilege'; Gate = $true; Action = { Get-MtUserPrivilege -Context $Context -UserId $userId } }
            @{ Name = 'Devices'; Gate = $true; Action = { Get-MtUserDevice -Context $Context -UserId $userId } }
            @{ Name = 'DirectoryChanges'; Gate = $capabilities.EntraIdP1; GateReason = 'Directory audit logs require Entra ID P1 or better.'; Action = { Get-MtUserDirectoryChange -Context $Context -UserId $userId -Days $Days } }
            @{ Name = 'Risk'; Gate = $capabilities.EntraIdP2; GateReason = 'Identity Protection requires Entra ID P2.'; Action = { Get-MtUserRisk -Context $Context -UserId $userId -Days $Days } }
        )

        foreach ($collector in $collectors) {
            $name = [string]$collector['Name']

            if (-not $collector['Gate']) {
                $reason = 'Not licensed.'
                if ($collector.ContainsKey('GateReason')) {
                    $reason = [string]$collector['GateReason']
                }
                $null = $investigation.NotChecked.Add([pscustomobject]@{ Source = $name; Reason = $reason })
                continue
            }

            try {
                $investigation.$name = & $collector['Action']
            }
            catch {
                $capturedStack = $_.ScriptStackTrace
                $null = $investigation.Errors.Add([pscustomobject]@{
                        Source     = $name
                        Message    = $_.Exception.Message
                        StackTrace = $capturedStack
                    })
                $null = $investigation.NotChecked.Add([pscustomobject]@{ Source = $name; Reason = 'Collection failed; see Errors.' })
                Write-MtLog -Level 'Warning' -Context $Context -Message ('Collector {0} failed: {1}' -f $name, $_.Exception.Message) -StackTrace $capturedStack
            }
        }

        # Inbox rules run last: they need the tenant domain list to classify
        # recipients, and that list is itself a collector above.
        try {
            $investigation.InboxRules = @(Get-MtUserInboxRule -Context $Context -UserId $userId -TenantDomain @($investigation.TenantDomains))
        }
        catch {
            $capturedStack = $_.ScriptStackTrace
            $null = $investigation.Errors.Add([pscustomobject]@{
                    Source     = 'InboxRules'
                    Message    = $_.Exception.Message
                    StackTrace = $capturedStack
                })
            $null = $investigation.NotChecked.Add([pscustomobject]@{ Source = 'InboxRules'; Reason = 'Collection failed; see Errors.' })
            Write-MtLog -Level 'Warning' -Context $Context -Message ('Collector InboxRules failed: {0}' -f $_.Exception.Message) -StackTrace $capturedStack
        }

        # Graph does not expose mailbox-level SMTP forwarding. Flag it every
        # time rather than let the report imply forwarding was fully checked.
        $null = $investigation.NotChecked.Add([pscustomobject]@{
                Source = 'MailboxForwarding'
                Reason = 'Mailbox-level ForwardingSmtpAddress is not exposed by Graph. Verify with Exchange Online PowerShell: Get-Mailbox -Identity <upn> | Select ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward'
            })

        $elapsed = ([DateTimeOffset]::UtcNow - $started).TotalSeconds
        Write-MtLog -Context $Context -Message ('Investigation of {0} complete in {1}s ({2} collector error(s)).' -f $upn, [math]::Round($elapsed, 1), $investigation.Errors.Count) -Data @{
            userId     = $userId
            signIns    = @($investigation.SignIns).Count
            rules      = @($investigation.InboxRules).Count
            grants     = @($investigation.OAuthGrants).Count
            notChecked = @($investigation.NotChecked).Count
        }

        return $investigation
    }
}
