function Get-MtInvestigationFinding {
    <#
    .SYNOPSIS
        Turns collected evidence into prioritized findings.

    .DESCRIPTION
        The difference between a data dump and a console. Each finding carries a
        severity, what was seen, and what to do about it.

        The rules encode the standard business email compromise pattern: an
        attacker forwards or hides mail so the victim never sees the replies,
        registers their own MFA method so a password reset does not evict them,
        and consents an application so neither does an MFA re-registration.

        Findings are evidence-based and deliberately noisy at Medium and below.
        A human decides; this ranks what they look at first.

    .EXAMPLE
        Get-MtInvestigationFinding -Investigation $investigation |
            Where-Object { $_.Severity -in 'Critical','High' }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Investigation
    )

    process {
        $findings = New-Object System.Collections.ArrayList
        $windowStart = ([DateTimeOffset]$Investigation.CollectedOn).AddDays(-$Investigation.LookbackDays)

        # ---- Inbox rules -------------------------------------------------
        $hidingFolders = @('rss feeds', 'rss subscriptions', 'conversation history', 'deleted items', 'junk email', 'archive', 'notes', 'sync issues')

        foreach ($rule in @($Investigation.InboxRules)) {
            $label = $rule.DisplayName
            if ([string]::IsNullOrWhiteSpace($label)) {
                $label = '(no name)'
            }

            if (@($rule.ExternalRecipients).Count -gt 0) {
                $severity = 'High'
                $state = 'disabled'
                if ($rule.IsEnabled) {
                    $severity = 'Critical'
                    $state = 'enabled'
                }

                $null = $findings.Add((New-MtFinding -Severity $severity -Category 'Mail forwarding' `
                            -Title ('Inbox rule "{0}" sends mail outside the organization' -f $label) `
                            -Detail ('Rule is {0} and forwards or redirects to: {1}' -f $state, (@($rule.ExternalRecipients) -join ', ')) `
                            -Recommendation 'Remove the rule, then check whether the recipient address appears in other mailboxes. Confirm mailbox-level forwarding separately in Exchange Online PowerShell.' `
                            -Evidence $rule))
            }

            if ($rule.PermanentDeletes) {
                $null = $findings.Add((New-MtFinding -Severity 'High' -Category 'Mail hiding' `
                            -Title ('Inbox rule "{0}" permanently deletes mail' -f $label) `
                            -Detail 'Hard delete bypasses Deleted Items, which is how a victim is kept from seeing replies to a fraudulent thread.' `
                            -Recommendation 'Remove the rule and check Purview audit for what it destroyed.' `
                            -Evidence $rule))
            }
            elseif ($rule.Deletes) {
                $null = $findings.Add((New-MtFinding -Severity 'Medium' -Category 'Mail hiding' `
                            -Title ('Inbox rule "{0}" deletes mail' -f $label) `
                            -Detail 'Moves matching mail to Deleted Items.' `
                            -Recommendation 'Confirm with the user that this rule is theirs.' `
                            -Evidence $rule))
            }

            if (-not [string]::IsNullOrWhiteSpace($rule.MoveToFolderName)) {
                if ($hidingFolders -contains $rule.MoveToFolderName.ToLowerInvariant()) {
                    $null = $findings.Add((New-MtFinding -Severity 'High' -Category 'Mail hiding' `
                                -Title ('Inbox rule "{0}" files mail into {1}' -f $label, $rule.MoveToFolderName) `
                                -Detail 'Moving inbound mail into a folder the user never opens is the classic way to hide a fraudulent thread in plain sight.' `
                                -Recommendation 'Remove the rule and review the destination folder for hidden correspondence.' `
                                -Evidence $rule))
                }
            }

            $trimmedName = ([string]$rule.DisplayName).Trim()
            if ($trimmedName.Length -le 2) {
                $null = $findings.Add((New-MtFinding -Severity 'High' -Category 'Mail hiding' `
                            -Title 'Inbox rule has a blank or single-character name' `
                            -Detail ('Rule name: "{0}". Attackers use "." or a single space so the rule is easy to miss in a rule list.' -f $rule.DisplayName) `
                            -Recommendation 'Treat as hostile until the user confirms otherwise.' `
                            -Evidence $rule))
            }
        }

        # ---- OAuth grants ------------------------------------------------
        foreach ($grant in @($Investigation.OAuthGrants)) {
            if (@($grant.RiskyScopes).Count -eq 0) {
                continue
            }

            $severity = $grant.HighestRisk
            if (-not $grant.VerifiedPublisher -and $severity -eq 'High') {
                $severity = 'Critical'
            }

            $publisherNote = 'unverified publisher'
            if ($grant.VerifiedPublisher) {
                $publisherNote = 'verified publisher'
            }

            $null = $findings.Add((New-MtFinding -Severity $severity -Category 'OAuth consent' `
                        -Title ('Application "{0}" holds sensitive delegated permissions' -f $grant.Application) `
                        -Detail ('{0}; scopes: {1}' -f $publisherNote, (@($grant.RiskyScopes) -join ', ')) `
                        -Recommendation 'Consent survives both a password reset and MFA re-registration. Revoke the grant, then check whether other users consented to the same application.' `
                        -Evidence $grant))
        }

        # ---- Authentication methods --------------------------------------
        foreach ($method in @($Investigation.AuthMethods)) {
            if ($null -eq $method.CreatedOn) {
                continue
            }

            $created = [DateTimeOffset]$method.CreatedOn
            if ($created -ge $windowStart) {
                $null = $findings.Add((New-MtFinding -Severity 'High' -Category 'Authentication' `
                            -Title ('Authentication method "{0}" registered during the investigation window' -f $method.Type) `
                            -Detail ('Registered {0} UTC. An attacker-registered method keeps access through a password reset.' -f (Format-MtTimestamp -Value $created)) `
                            -Recommendation 'Confirm with the user out of band. If unrecognized, remove the method before resetting the password.' `
                            -Evidence $method))
            }
        }

        # ---- Directory audit ---------------------------------------------
        if ($null -ne $Investigation.DirectoryChanges) {
            $securityKeywords = @('security info', 'strong authentication', 'authentication method', 'password')

            foreach ($entry in @($Investigation.DirectoryChanges.TargetingUser)) {
                $activity = [string](Get-MtContainmentProperty -InputObject $entry -Name 'activityDisplayName' -Default '')
                $lower = $activity.ToLowerInvariant()

                $matched = $false
                foreach ($keyword in $securityKeywords) {
                    if ($lower.Contains($keyword)) {
                        $matched = $true
                        break
                    }
                }

                if ($matched) {
                    $initiator = Get-MtContainmentProperty -InputObject $entry -Name 'initiatedBy' -Default $null
                    $initiatorUser = Get-MtContainmentProperty -InputObject $initiator -Name 'user' -Default $null
                    $initiatorName = [string](Get-MtContainmentProperty -InputObject $initiatorUser -Name 'userPrincipalName' -Default 'unknown')

                    $null = $findings.Add((New-MtFinding -Severity 'High' -Category 'Authentication' `
                                -Title ('Credential change on the account: {0}' -f $activity) `
                                -Detail ('Initiated by {0} at {1} UTC.' -f $initiatorName, (Format-MtTimestamp -Value (Get-MtContainmentProperty -InputObject $entry -Name 'activityDateTime' -Default $null))) `
                                -Recommendation 'Verify the initiator was a legitimate administrator or the user themselves.' `
                                -Evidence $entry))
                }
            }

            $initiatedCount = @($Investigation.DirectoryChanges.InitiatedByUser).Count
            if ($initiatedCount -gt 0) {
                $null = $findings.Add((New-MtFinding -Severity 'Medium' -Category 'Blast radius' `
                            -Title ('Account made {0} directory change(s) during the window' -f $initiatedCount) `
                            -Detail 'Changes made by this account while it may have been under attacker control.' `
                            -Recommendation 'Review each change and reverse anything the user does not recognize.' `
                            -Evidence @($Investigation.DirectoryChanges.InitiatedByUser)))
            }
        }

        # ---- Privilege and blast radius ----------------------------------
        if ($null -ne $Investigation.Privilege) {
            $roles = @($Investigation.Privilege.DirectoryRoles)
            if ($roles.Count -gt 0) {
                $null = $findings.Add((New-MtFinding -Severity 'High' -Category 'Blast radius' `
                            -Title ('Account holds {0} directory role(s)' -f $roles.Count) `
                            -Detail ('Roles: {0}. This is a tenant incident, not a mailbox incident.' -f ((@($roles) | ForEach-Object { $_.DisplayName }) -join ', ')) `
                            -Recommendation 'Escalate scope. Review the tenant audit log for changes made during the window, not just this account.' `
                            -Evidence $roles))
            }

            $ownedApps = @($Investigation.Privilege.OwnedObjects | Where-Object { @('application', 'servicePrincipal') -contains $_.Type })
            if ($ownedApps.Count -gt 0) {
                $null = $findings.Add((New-MtFinding -Severity 'High' -Category 'Persistence' `
                            -Title ('Account owns {0} application object(s)' -f $ownedApps.Count) `
                            -Detail ('Owned: {0}. An owner can add a credential to an app and retain tenant access indefinitely.' -f ((@($ownedApps) | ForEach-Object { $_.DisplayName }) -join ', ')) `
                            -Recommendation 'Inspect each application for credentials added during the window.' `
                            -Evidence $ownedApps))
            }
        }

        # ---- Sign-in analysis --------------------------------------------
        $signIns = @($Investigation.SignIns)
        if ($signIns.Count -gt 0) {
            $successful = New-Object System.Collections.ArrayList
            $countries = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
            $legacyClients = @{}

            foreach ($signIn in $signIns) {
                $status = Get-MtContainmentProperty -InputObject $signIn -Name 'status' -Default $null
                $errorCode = [int](Get-MtContainmentProperty -InputObject $status -Name 'errorCode' -Default -1)

                if ($errorCode -ne 0) {
                    continue
                }

                $null = $successful.Add($signIn)

                $location = Get-MtContainmentProperty -InputObject $signIn -Name 'location' -Default $null
                $country = [string](Get-MtContainmentProperty -InputObject $location -Name 'countryOrRegion' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($country)) {
                    $null = $countries.Add($country)
                }

                $client = [string](Get-MtContainmentProperty -InputObject $signIn -Name 'clientAppUsed' -Default '')
                if (@('IMAP4', 'POP3', 'SMTP', 'Other clients', 'Exchange ActiveSync', 'Authenticated SMTP', 'MAPI Over HTTP', 'Offline Address Book') -contains $client) {
                    if (-not $legacyClients.ContainsKey($client)) {
                        $legacyClients[$client] = 0
                    }
                    $legacyClients[$client] = $legacyClients[$client] + 1
                }
            }

            foreach ($client in $legacyClients.Keys) {
                $null = $findings.Add((New-MtFinding -Severity 'High' -Category 'Sign-in' `
                            -Title ('Successful sign-in over legacy protocol: {0}' -f $client) `
                            -Detail ('{0} successful authentication(s). Legacy protocols do not support modern authentication and are the standard route past MFA.' -f $legacyClients[$client]) `
                            -Recommendation 'Block legacy authentication tenant-wide with Conditional Access if it is not already blocked.' `
                            -Evidence $client))
            }

            if ($countries.Count -gt 1) {
                $null = $findings.Add((New-MtFinding -Severity 'Medium' -Category 'Sign-in' `
                            -Title ('Successful sign-ins from {0} countries' -f $countries.Count) `
                            -Detail ('Countries seen: {0}' -f ((@($countries) | Sort-Object) -join ', ')) `
                            -Recommendation 'Compare against the user''s expected travel. Multiple countries in a short window is the cheapest impossible-travel check you have without P2.' `
                            -Evidence (@($countries) | Sort-Object)))
            }

            $null = $findings.Add((New-MtFinding -Severity 'Info' -Category 'Sign-in' `
                        -Title ('{0} successful sign-in(s) of {1} total in the window' -f $successful.Count, $signIns.Count) `
                        -Detail ('Lookback: {0} day(s).' -f $Investigation.LookbackDays) `
                        -Recommendation '' `
                        -Evidence $null))
        }

        # ---- Identity Protection -----------------------------------------
        if ($null -ne $Investigation.Risk -and $Investigation.Risk.Licensed) {
            $riskyUser = $Investigation.Risk.RiskyUser
            $riskLevel = [string](Get-MtContainmentProperty -InputObject $riskyUser -Name 'riskLevel' -Default 'none')
            $riskState = [string](Get-MtContainmentProperty -InputObject $riskyUser -Name 'riskState' -Default 'none')

            if (@('high', 'medium', 'low') -contains $riskLevel.ToLowerInvariant()) {
                $severity = 'Medium'
                if ($riskLevel.ToLowerInvariant() -eq 'high') {
                    $severity = 'Critical'
                }
                elseif ($riskLevel.ToLowerInvariant() -eq 'medium') {
                    $severity = 'High'
                }

                $null = $findings.Add((New-MtFinding -Severity $severity -Category 'Identity Protection' `
                            -Title ('Identity Protection risk level: {0}' -f $riskLevel) `
                            -Detail ('Risk state: {0}. Detections in window: {1}.' -f $riskState, @($Investigation.Risk.Detections).Count) `
                            -Recommendation 'Confirm compromised in Identity Protection once containment is done, so the signal feeds back into risk policies.' `
                            -Evidence $riskyUser))
            }
        }

        # ---- Current account state ---------------------------------------
        $enabled = [bool](Get-MtContainmentProperty -InputObject $Investigation.Account -Name 'accountEnabled' -Default $true)
        if ($enabled) {
            $null = $findings.Add((New-MtFinding -Severity 'Info' -Category 'Account state' `
                        -Title 'Account is currently enabled' `
                        -Detail 'No containment has been applied to sign-in state.' `
                        -Recommendation 'If the findings above warrant it, run Invoke-MtAccountContainment against an armed context.' `
                        -Evidence $null))
        }
        else {
            $null = $findings.Add((New-MtFinding -Severity 'Info' -Category 'Account state' `
                        -Title 'Account is currently disabled' `
                        -Detail 'Sign-in is already blocked.' `
                        -Recommendation '' `
                        -Evidence $null))
        }

        # ---- Coverage gaps -----------------------------------------------
        foreach ($gap in @($Investigation.NotChecked)) {
            $null = $findings.Add((New-MtFinding -Severity 'Low' -Category 'Coverage gap' `
                        -Title ('Not checked: {0}' -f $gap.Source) `
                        -Detail $gap.Reason `
                        -Recommendation 'Close this gap before calling the investigation complete.' `
                        -Evidence $null))
        }

        return @($findings | Sort-Object -Property @{ Expression = { Get-MtSeverityRank -Severity $_.Severity } }, Category, Title)
    }
}
