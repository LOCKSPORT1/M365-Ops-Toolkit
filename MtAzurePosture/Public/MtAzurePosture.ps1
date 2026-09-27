function Get-MtAzurePosture {
    <#
    .SYNOPSIS
        Runs the full read-only sweep across one or more subscriptions.

    .DESCRIPTION
        Every call is a GET. Nothing in this module mutates anything, and no
        write scope is required to run it -- which is the point: an engineer
        holding Contributor, or even Reader, can produce the whole report
        without asking for elevated access.

        Each collector is wrapped independently, and a denied scope is recorded
        as a coverage gap rather than an empty result. "No findings" and "could
        not look" must never render the same way.

    .EXAMPLE
        $posture = Get-MtAzurePosture -Context $ctx
        Get-MtAzureFinding -Posture $posture | Format-Table Severity, Category, Title

    .EXAMPLE
        Get-MtAzurePosture -Context $ctx -SubscriptionId '0000...' |
            Export-MtAzureReport -Path .\sweep
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Context,

        [string[]]$SubscriptionId
    )

    process {
        $started = [DateTimeOffset]::UtcNow
        Write-MtLog -Context $Context -Message 'Starting Azure posture sweep.'

        $subscriptions = @(Get-MtAzureSubscription -Context $Context)

        if ($null -ne $SubscriptionId -and $SubscriptionId.Count -gt 0) {
            $subscriptions = @($subscriptions | Where-Object { $SubscriptionId -contains $_.SubscriptionId })
        }

        $results = New-Object System.Collections.ArrayList
        $gaps = New-Object System.Collections.ArrayList

        foreach ($subscription in $subscriptions) {
            $id = $subscription.SubscriptionId
            $label = $subscription.DisplayName

            Write-MtLog -Context $Context -Message ('Sweeping subscription {0} ({1}).' -f $label, $id)

            $entry = [pscustomobject]@{
                SubscriptionId = $id
                DisplayName    = $label
                State          = $subscription.State
                Rbac           = $null
                Network        = $null
                Storage        = $null
                Compute        = $null
                Policy         = $null
                Monitoring     = $null
            }

            $collectors = @(
                @{ Name = 'Rbac'; Action = { Get-MtAzureRoleAssignment -Context $Context -SubscriptionId $id } }
                @{ Name = 'Network'; Action = { Get-MtAzureNetworkExposure -Context $Context -SubscriptionId $id } }
                @{ Name = 'Storage'; Action = { Get-MtAzureStorageAccount -Context $Context -SubscriptionId $id } }
                @{ Name = 'Compute'; Action = { Get-MtAzureComputeHygiene -Context $Context -SubscriptionId $id } }
                @{ Name = 'Policy'; Action = { Get-MtAzurePolicyState -Context $Context -SubscriptionId $id } }
                @{ Name = 'Monitoring'; Action = { Get-MtAzureMonitoring -Context $Context -SubscriptionId $id } }
            )

            foreach ($collector in $collectors) {
                $name = [string]$collector['Name']

                try {
                    $collected = & $collector['Action']
                    $entry.$name = $collected

                    if ([bool](Get-MtAzProperty -InputObject $collected -Name 'Denied' -Default $false)) {
                        $null = $gaps.Add([pscustomobject]@{
                                Subscription = $label
                                Source       = $name
                                Reason       = 'Access denied on at least one read. The signed-in principal lacks permission on this scope.'
                            })
                    }
                }
                catch {
                    $capturedStack = $_.ScriptStackTrace
                    $null = $gaps.Add([pscustomobject]@{
                            Subscription = $label
                            Source       = $name
                            Reason       = ('Collection failed: {0}' -f $_.Exception.Message)
                        })
                    Write-MtLog -Level 'Warning' -Context $Context -Message ('Collector {0} failed on {1}: {2}' -f $name, $label, $_.Exception.Message) -StackTrace $capturedStack
                }
            }

            $null = $results.Add($entry)
        }

        $elapsed = ([DateTimeOffset]::UtcNow - $started).TotalSeconds
        Write-MtLog -Context $Context -Message ('Azure sweep complete in {0}s across {1} subscription(s), {2} coverage gap(s).' -f [math]::Round($elapsed, 1), $results.Count, $gaps.Count)

        return [pscustomobject]@{
            PSTypeName    = 'MtAzure.Posture'
            Tenant        = $Context.Name
            TenantId      = $Context.TenantId
            Cloud         = $Context.Cloud
            CollectedOn   = $started
            Subscriptions = @($results)
            NotChecked    = @($gaps)
        }
    }
}

function Get-MtAzureFinding {
    <#
    .SYNOPSIS
        Turns a posture sweep into prioritized findings.

    .DESCRIPTION
        Ordered so the things that get an estate owned come first: internet
        exposure to management ports, then storage and identity posture, then
        resilience, then cost and hygiene.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Posture
    )

    process {
        $findings = New-Object System.Collections.ArrayList

        foreach ($subscription in @($Posture.Subscriptions)) {
            $label = $subscription.DisplayName

            # ---- Network exposure ----------------------------------------
            if ($null -ne $subscription.Network) {
                foreach ($exposure in @($subscription.Network.Exposures)) {
                    $named = New-Object System.Collections.ArrayList
                    foreach ($port in @($exposure.ExposedPorts)) {
                        $portName = Get-MtAdminPortName -Port $port
                        if ([string]::IsNullOrWhiteSpace($portName)) {
                            $null = $named.Add([string]$port)
                        }
                        else {
                            $null = $named.Add(('{0} ({1})' -f $port, $portName))
                        }
                    }

                    if ($named.Count -eq 0) {
                        continue
                    }

                    $severity = 'High'
                    if ($exposure.Attached) {
                        $severity = 'Critical'
                    }

                    $attachNote = 'not attached to any subnet or interface, so not currently effective'
                    if ($exposure.Attached) {
                        $attachNote = 'attached and in effect'
                    }

                    $null = $findings.Add((New-MtAzFinding -Severity $severity -Category 'Network exposure' `
                                -Subscription $label -Resource $exposure.NsgName `
                                -Title ('NSG rule "{0}" allows the internet inbound to management ports' -f $exposure.RuleName) `
                                -Detail ('Ports: {0}. Source: {1}. Protocol: {2}. The NSG is {3}.' -f (($named) -join ', '), ((@($exposure.Sources)) -join ', '), $exposure.Protocol, $attachNote) `
                                -Recommendation 'Restrict the source to known prefixes, or front the access with Bastion or a VPN. Wide-open RDP and SQL are the most commonly exploited Azure misconfigurations.' `
                                -Evidence $exposure))
                }

                foreach ($nsg in @($subscription.Network.UnattachedNsgs)) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Low' -Category 'Hygiene' `
                                -Subscription $label -Resource $nsg.Name `
                                -Title 'Network security group is attached to nothing' `
                                -Detail 'The NSG exists but governs no subnet or interface. Its rules give a false sense of coverage.' `
                                -Recommendation 'Attach it or remove it.' -Evidence $nsg))
                }

                foreach ($ip in @($subscription.Network.OrphanedIps)) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Low' -Category 'Cost' `
                                -Subscription $label -Resource $ip.Name `
                                -Title 'Public IP address is not associated with anything' `
                                -Detail 'Standard SKU public IPs bill whether or not they are attached.' `
                                -Recommendation 'Release it if it is not reserved for a planned deployment.' -Evidence $ip))
                }

                foreach ($nic in @($subscription.Network.OrphanedNics)) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Low' -Category 'Hygiene' `
                                -Subscription $label -Resource $nic.Name `
                                -Title 'Network interface is not attached to a virtual machine' `
                                -Detail 'Left behind by a deleted VM.' `
                                -Recommendation 'Remove it.' -Evidence $nic))
                }
            }

            # ---- Storage --------------------------------------------------
            if ($null -ne $subscription.Storage) {
                foreach ($account in @($subscription.Storage.Accounts)) {
                    if ($account.AllowBlobPublicAccess) {
                        $null = $findings.Add((New-MtAzFinding -Severity 'High' -Category 'Storage' `
                                    -Subscription $label -Resource $account.Name `
                                    -Title 'Storage account permits anonymous blob access' `
                                    -Detail 'allowBlobPublicAccess is enabled, so a container can be set to public without further approval.' `
                                    -Recommendation 'Disable it at the account level unless a container is deliberately public.' -Evidence $account))
                    }

                    if (-not $account.HttpsOnly) {
                        $null = $findings.Add((New-MtAzFinding -Severity 'High' -Category 'Storage' `
                                    -Subscription $label -Resource $account.Name `
                                    -Title 'Storage account accepts unencrypted HTTP' `
                                    -Detail 'supportsHttpsTrafficOnly is disabled; credentials and data can travel in the clear.' `
                                    -Recommendation 'Enable HTTPS-only transport.' -Evidence $account))
                    }

                    if (-not [string]::IsNullOrWhiteSpace($account.MinimumTlsVersion) -and $account.MinimumTlsVersion -ne 'TLS1_2' -and $account.MinimumTlsVersion -ne 'TLS1_3') {
                        $null = $findings.Add((New-MtAzFinding -Severity 'Medium' -Category 'Storage' `
                                    -Subscription $label -Resource $account.Name `
                                    -Title ('Storage account allows {0}' -f $account.MinimumTlsVersion) `
                                    -Detail 'Deprecated TLS versions remain negotiable.' `
                                    -Recommendation 'Raise the minimum to TLS 1.2.' -Evidence $account))
                    }

                    if ($account.NetworkDefaultAction -eq 'Allow') {
                        $null = $findings.Add((New-MtAzFinding -Severity 'Medium' -Category 'Storage' `
                                    -Subscription $label -Resource $account.Name `
                                    -Title 'Storage account is reachable from any network' `
                                    -Detail 'networkAcls defaultAction is Allow, so no firewall or private endpoint restriction applies.' `
                                    -Recommendation 'Set the default action to Deny and allow specific networks or private endpoints.' -Evidence $account))
                    }
                }
            }

            # ---- RBAC ------------------------------------------------------
            if ($null -ne $subscription.Rbac) {
                $owners = @($subscription.Rbac.Assignments | Where-Object { $_.RoleName -eq 'Owner' })
                $userOwners = @($owners | Where-Object { $_.PrincipalType -eq 'User' })

                if ($userOwners.Count -gt 0) {
                    $severity = 'Medium'
                    if ($userOwners.Count -gt 3) {
                        $severity = 'High'
                    }

                    $null = $findings.Add((New-MtAzFinding -Severity $severity -Category 'Identity' `
                                -Subscription $label -Resource 'subscription scope' `
                                -Title ('{0} user principal(s) hold Owner at subscription scope' -f $userOwners.Count) `
                                -Detail 'Owner includes the right to grant further access. Assigning it to individuals rather than a group makes review and offboarding manual.' `
                                -Recommendation 'Move standing Owner to a group, or to PIM-eligible assignment if Entra ID P2 is available.' -Evidence $userOwners))
                }

                if (@($subscription.Rbac.ClassicAdmins).Count -gt 0) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Medium' -Category 'Identity' `
                                -Subscription $label -Resource 'subscription scope' `
                                -Title ('{0} classic administrator(s) still assigned' -f @($subscription.Rbac.ClassicAdmins).Count) `
                                -Detail 'Classic administrators predate RBAC, are invisible in most access reviews, and carry co-administrator rights.' `
                                -Recommendation 'Remove them and reassign through RBAC.' -Evidence @($subscription.Rbac.ClassicAdmins)))
                }

                if (-not $subscription.Rbac.DefinitionsResolved) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Low' -Category 'Coverage gap' `
                                -Subscription $label -Resource 'roleDefinitions' `
                                -Title 'Role definitions could not be read' `
                                -Detail 'Assignments are reported by role GUID rather than name.' `
                                -Recommendation 'Grant read on Microsoft.Authorization/roleDefinitions for a complete picture.'))
                }
            }

            # ---- Compute and resilience -------------------------------------
            if ($null -ne $subscription.Compute) {
                $unprotected = @($subscription.Compute.VirtualMachines | Where-Object { -not $_.BackedUp })

                if ($unprotected.Count -gt 0 -and $subscription.Compute.BackupReadable) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'High' -Category 'Resilience' `
                                -Subscription $label -Resource 'virtual machines' `
                                -Title ('{0} virtual machine(s) have no backup protection' -f $unprotected.Count) `
                                -Detail ('Unprotected: {0}' -f ((@($unprotected) | ForEach-Object { $_.Name }) -join ', ')) `
                                -Recommendation 'Enrol them in a Recovery Services vault policy, or document why they are disposable.' -Evidence $unprotected))
                }

                if (-not $subscription.Compute.BackupReadable) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Low' -Category 'Coverage gap' `
                                -Subscription $label -Resource 'Recovery Services' `
                                -Title 'Backup protection state could not be fully read' `
                                -Detail 'At least one vault denied the protected items list, so backup coverage is unknown rather than absent.' `
                                -Recommendation 'Grant read on Microsoft.RecoveryServices before treating this as a clean result.'))
                }

                foreach ($disk in @($subscription.Compute.UnattachedDisks)) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Low' -Category 'Cost' `
                                -Subscription $label -Resource $disk.Name `
                                -Title 'Managed disk is unattached' `
                                -Detail ('{0} GB billing with no VM attached.' -f $disk.SizeGb) `
                                -Recommendation 'Snapshot and delete, or reattach.' -Evidence $disk))
                }
            }

            # ---- Policy ------------------------------------------------------
            if ($null -ne $subscription.Policy) {
                if ($subscription.Policy.AssignmentCount -eq 0 -and -not $subscription.Policy.Denied) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Medium' -Category 'Governance' `
                                -Subscription $label -Resource 'subscription scope' `
                                -Title 'No Azure Policy assignments at subscription scope' `
                                -Detail 'Nothing is enforcing configuration standards; drift is invisible until someone looks.' `
                                -Recommendation 'Start with a built-in initiative covering the controls you already care about.'))
                }

                if ($subscription.Policy.NonCompliantResources -gt 0) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Medium' -Category 'Governance' `
                                -Subscription $label -Resource 'policy compliance' `
                                -Title ('{0} resource(s) non-compliant with assigned policy' -f $subscription.Policy.NonCompliantResources) `
                                -Detail 'Policy is assigned and reporting failures.' `
                                -Recommendation 'Triage by initiative; remediate or document an exemption.'))
                }

                if (-not $subscription.Policy.SummaryReadable) {
                    $null = $findings.Add((New-MtAzFinding -Severity 'Low' -Category 'Coverage gap' `
                                -Subscription $label -Resource 'Policy Insights' `
                                -Title 'Policy compliance summary could not be read' `
                                -Detail 'Policy Insights is commonly denied to a plain Contributor. Compliance state is unknown, not clean.' `
                                -Recommendation 'Grant Resource Policy Contributor or Reader at subscription scope.'))
                }
            }

            # ---- Monitoring ---------------------------------------------------
            if ($null -ne $subscription.Monitoring) {
                foreach ($alert in @($subscription.Monitoring.AlertRules)) {
                    if ($alert.ActionCount -eq 0) {
                        $null = $findings.Add((New-MtAzFinding -Severity 'Medium' -Category 'Monitoring' `
                                    -Subscription $label -Resource $alert.Name `
                                    -Title 'Alert rule has no action group' `
                                    -Detail 'The rule evaluates and fires, and nobody is told. It looks healthy in the portal.' `
                                    -Recommendation 'Attach an action group or disable the rule.' -Evidence $alert))
                    }
                }

                foreach ($group in @($subscription.Monitoring.ActionGroups)) {
                    if ($group.ReceiverCount -eq 0) {
                        $null = $findings.Add((New-MtAzFinding -Severity 'Medium' -Category 'Monitoring' `
                                    -Subscription $label -Resource $group.Name `
                                    -Title 'Action group has no receivers' `
                                    -Detail 'Alerts routed here reach nobody.' `
                                    -Recommendation 'Add an email, SMS or webhook receiver.' -Evidence $group))
                    }
                }

                foreach ($workspace in @($subscription.Monitoring.Workspaces)) {
                    if ($workspace.RetentionDays -gt 0 -and $workspace.RetentionDays -lt 90) {
                        $null = $findings.Add((New-MtAzFinding -Severity 'Low' -Category 'Monitoring' `
                                    -Subscription $label -Resource $workspace.Name `
                                    -Title ('Log Analytics retention is {0} days' -f $workspace.RetentionDays) `
                                    -Detail 'Shorter than the 90 days most incident investigations and compliance frameworks assume.' `
                                    -Recommendation 'Raise retention, or archive to storage if cost is the constraint.' -Evidence $workspace))
                    }
                }
            }
        }

        # ---- Coverage gaps ----------------------------------------------------
        foreach ($gap in @($Posture.NotChecked)) {
            $null = $findings.Add((New-MtAzFinding -Severity 'Low' -Category 'Coverage gap' `
                        -Subscription $gap.Subscription -Resource $gap.Source `
                        -Title ('Not checked: {0}' -f $gap.Source) `
                        -Detail $gap.Reason `
                        -Recommendation 'Close this gap before calling the sweep complete.'))
        }

        return @($findings | Sort-Object -Property @{ Expression = { Get-MtAzSeverityRank -Severity $_.Severity } }, Category, Subscription, Title)
    }
}

function Export-MtAzureReport {
    <#
    .SYNOPSIS
        Writes posture.json, findings.json and report.md.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Posture,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [string]$Ticket = '',

        [AllowNull()]
        [object[]]$Finding = $null
    )

    process {
        if (-not (Test-Path -LiteralPath $Path)) {
            $null = New-Item -Path $Path -ItemType Directory -Force
        }

        if ($null -eq $Finding) {
            $Finding = @(Get-MtAzureFinding -Posture $Posture)
        }

        $posturePath = Join-Path -Path $Path -ChildPath 'posture.json'
        $findingsPath = Join-Path -Path $Path -ChildPath 'findings.json'
        $reportPath = Join-Path -Path $Path -ChildPath 'report.md'

        $Posture | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $posturePath -Encoding UTF8
        @($Finding) | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $findingsPath -Encoding UTF8

        $markdown = New-Object System.Text.StringBuilder
        $null = $markdown.AppendLine('# Azure posture sweep')
        $null = $markdown.AppendLine('')
        if (-not [string]::IsNullOrWhiteSpace($Ticket)) {
            $null = $markdown.AppendLine(('- **Ticket:** {0}' -f $Ticket))
        }
        $null = $markdown.AppendLine(('- **Tenant:** {0}' -f $Posture.Tenant))
        $null = $markdown.AppendLine(('- **Cloud:** {0}' -f $Posture.Cloud))
        $null = $markdown.AppendLine(('- **Collected (UTC):** {0}' -f ([DateTimeOffset]$Posture.CollectedOn).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)))
        $null = $markdown.AppendLine(('- **Subscriptions swept:** {0}' -f @($Posture.Subscriptions).Count))
        $null = $markdown.AppendLine('')
        $null = $markdown.AppendLine('All reads. This sweep makes no changes and requires no write permission.')
        $null = $markdown.AppendLine('')

        $bySeverity = @{}
        foreach ($item in @($Finding)) {
            if (-not $bySeverity.ContainsKey($item.Severity)) {
                $bySeverity[$item.Severity] = 0
            }
            $bySeverity[$item.Severity] = $bySeverity[$item.Severity] + 1
        }

        $null = $markdown.AppendLine('## Summary')
        $null = $markdown.AppendLine('')
        foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            $count = 0
            if ($bySeverity.ContainsKey($severity)) {
                $count = $bySeverity[$severity]
            }
            $null = $markdown.AppendLine(('- {0}: {1}' -f $severity, $count))
        }
        $null = $markdown.AppendLine('')

        $actionable = @($Finding | Where-Object { @('Critical', 'High', 'Medium') -contains $_.Severity })

        if ($actionable.Count -gt 0) {
            $null = $markdown.AppendLine('## Findings')
            $null = $markdown.AppendLine('')
            foreach ($item in $actionable) {
                $null = $markdown.AppendLine(('### [{0}] {1}' -f $item.Severity, $item.Title))
                $null = $markdown.AppendLine('')
                $null = $markdown.AppendLine(('*{0} — {1} / {2}*' -f $item.Category, $item.Subscription, $item.Resource))
                $null = $markdown.AppendLine('')
                if (-not [string]::IsNullOrWhiteSpace($item.Detail)) {
                    $null = $markdown.AppendLine($item.Detail)
                    $null = $markdown.AppendLine('')
                }
                if (-not [string]::IsNullOrWhiteSpace($item.Recommendation)) {
                    $null = $markdown.AppendLine(('**Action:** {0}' -f $item.Recommendation))
                    $null = $markdown.AppendLine('')
                }
            }
        }

        $null = $markdown.AppendLine('## Inventory')
        $null = $markdown.AppendLine('')
        $null = $markdown.AppendLine('| Subscription | NSGs | Storage | VMs | Workspaces | Alert rules |')
        $null = $markdown.AppendLine('| --- | --- | --- | --- | --- | --- |')
        foreach ($subscription in @($Posture.Subscriptions)) {
            $nsgCount = 0
            if ($null -ne $subscription.Network) { $nsgCount = $subscription.Network.NsgCount }
            $storageCount = 0
            if ($null -ne $subscription.Storage) { $storageCount = @($subscription.Storage.Accounts).Count }
            $vmCount = 0
            if ($null -ne $subscription.Compute) { $vmCount = @($subscription.Compute.VirtualMachines).Count }
            $workspaceCount = 0
            $alertCount = 0
            if ($null -ne $subscription.Monitoring) {
                $workspaceCount = @($subscription.Monitoring.Workspaces).Count
                $alertCount = @($subscription.Monitoring.AlertRules).Count
            }

            $null = $markdown.AppendLine(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $subscription.DisplayName, $nsgCount, $storageCount, $vmCount, $workspaceCount, $alertCount))
        }
        $null = $markdown.AppendLine('')

        $gaps = @($Posture.NotChecked)
        if ($gaps.Count -gt 0) {
            $null = $markdown.AppendLine('## Not checked')
            $null = $markdown.AppendLine('')
            foreach ($gap in $gaps) {
                $null = $markdown.AppendLine(('- **{0} / {1}** — {2}' -f $gap.Subscription, $gap.Source, $gap.Reason))
            }
            $null = $markdown.AppendLine('')
        }

        $markdown.ToString() | Set-Content -LiteralPath $reportPath -Encoding UTF8

        return [pscustomobject]@{
            ReportPath   = $reportPath
            PosturePath  = $posturePath
            FindingsPath = $findingsPath
        }
    }
}
