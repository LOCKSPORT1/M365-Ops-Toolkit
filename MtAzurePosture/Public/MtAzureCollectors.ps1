function Get-MtAzureSubscription {
    <#
    .SYNOPSIS
        Lists subscriptions the signed-in principal can see.

    .EXAMPLE
        Get-MtAzureSubscription -Context $ctx | Format-Table displayName, subscriptionId, state
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Context
    )

    process {
        $result = Invoke-MtAzRequest -Context $Context -Uri 'subscriptions' -ApiVersion (Get-MtAzApiVersion -Provider 'subscriptions')

        if (-not $result.Success) {
            throw "Could not list subscriptions: $($result.Message)"
        }

        foreach ($subscription in $result.Items) {
            [pscustomobject]@{
                SubscriptionId = [string](Get-MtAzProperty -InputObject $subscription -Name 'subscriptionId' -Default '')
                DisplayName    = [string](Get-MtAzProperty -InputObject $subscription -Name 'displayName' -Default '')
                State          = [string](Get-MtAzProperty -InputObject $subscription -Name 'state' -Default '')
                TenantId       = [string](Get-MtAzProperty -InputObject $subscription -Name 'tenantId' -Default '')
                Raw            = $subscription
            }
        }
    }
}

function Get-MtAzureRoleAssignment {
    <#
    .SYNOPSIS
        Role assignments at subscription scope, with role definitions resolved.

    .DESCRIPTION
        Reading role assignments requires Microsoft.Authorization/roleAssignments/read,
        which Contributor does have -- but reading role DEFINITIONS to turn a
        GUID into "Owner" needs the same, and some custom scopes deny it. When
        the definition cannot be resolved the GUID is reported rather than
        dropping the assignment.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $scope = 'subscriptions/{0}' -f $SubscriptionId
    $assignmentUri = '{0}/providers/Microsoft.Authorization/roleAssignments' -f $scope
    $assignments = Invoke-MtAzRequest -Context $Context -Uri $assignmentUri -ApiVersion (Get-MtAzApiVersion -Provider 'roleAssignments')

    $definitionUri = '{0}/providers/Microsoft.Authorization/roleDefinitions' -f $scope
    $definitions = Invoke-MtAzRequest -Context $Context -Uri $definitionUri -ApiVersion (Get-MtAzApiVersion -Provider 'roleDefinitions')

    $definitionNames = @{}
    if ($definitions.Success) {
        foreach ($definition in $definitions.Items) {
            $id = [string](Get-MtAzProperty -InputObject $definition -Name 'id' -Default '')
            $properties = Get-MtAzProperty -InputObject $definition -Name 'properties' -Default $null
            $name = [string](Get-MtAzProperty -InputObject $properties -Name 'roleName' -Default '')
            if (-not [string]::IsNullOrWhiteSpace($id)) {
                $definitionNames[$id] = $name
            }
        }
    }

    $classicUri = '{0}/providers/Microsoft.Authorization/classicAdministrators' -f $scope
    $classic = Invoke-MtAzRequest -Context $Context -Uri $classicUri -ApiVersion (Get-MtAzApiVersion -Provider 'classicAdmins')

    $rows = New-Object System.Collections.ArrayList
    foreach ($assignment in $assignments.Items) {
        $properties = Get-MtAzProperty -InputObject $assignment -Name 'properties' -Default $null
        $definitionId = [string](Get-MtAzProperty -InputObject $properties -Name 'roleDefinitionId' -Default '')

        $roleName = ''
        if ($definitionNames.ContainsKey($definitionId)) {
            $roleName = $definitionNames[$definitionId]
        }
        if ([string]::IsNullOrWhiteSpace($roleName)) {
            $roleName = ($definitionId -split '/')[-1]
        }

        $null = $rows.Add([pscustomobject]@{
                Id                = [string](Get-MtAzProperty -InputObject $assignment -Name 'id' -Default '')
                RoleName          = $roleName
                PrincipalId       = [string](Get-MtAzProperty -InputObject $properties -Name 'principalId' -Default '')
                PrincipalType     = [string](Get-MtAzProperty -InputObject $properties -Name 'principalType' -Default '')
                Scope             = [string](Get-MtAzProperty -InputObject $properties -Name 'scope' -Default '')
                IsSubscriptionScope = ([string](Get-MtAzProperty -InputObject $properties -Name 'scope' -Default '') -eq ('/subscriptions/{0}' -f $SubscriptionId))
                CreatedOn         = (Get-MtAzProperty -InputObject $properties -Name 'createdOn' -Default $null)
            })
    }

    return [pscustomobject]@{
        Assignments          = @($rows)
        ClassicAdmins        = @($classic.Items)
        AssignmentsDenied    = $assignments.Denied
        DefinitionsResolved  = $definitions.Success
        ClassicDenied        = $classic.Denied
        Message              = $assignments.Message
    }
}

function Get-MtAzureNetworkExposure {
    <#
    .SYNOPSIS
        Network security groups, public IPs and their attachment state.

    .DESCRIPTION
        The highest-value read in the whole sweep. An NSG rule allowing the
        internet inbound to RDP or SQL is the single most common way an Azure
        estate gets owned, and it is trivially findable if anyone looks.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $apiVersion = Get-MtAzApiVersion -Provider 'network'
    $base = 'subscriptions/{0}/providers/Microsoft.Network' -f $SubscriptionId

    $nsgs = Invoke-MtAzRequest -Context $Context -Uri ('{0}/networkSecurityGroups' -f $base) -ApiVersion $apiVersion
    $publicIps = Invoke-MtAzRequest -Context $Context -Uri ('{0}/publicIPAddresses' -f $base) -ApiVersion $apiVersion
    $nics = Invoke-MtAzRequest -Context $Context -Uri ('{0}/networkInterfaces' -f $base) -ApiVersion $apiVersion

    $exposures = New-Object System.Collections.ArrayList
    $unattachedNsgs = New-Object System.Collections.ArrayList

    foreach ($nsg in $nsgs.Items) {
        $nsgName = [string](Get-MtAzProperty -InputObject $nsg -Name 'name' -Default '')
        $nsgId = [string](Get-MtAzProperty -InputObject $nsg -Name 'id' -Default '')
        $properties = Get-MtAzProperty -InputObject $nsg -Name 'properties' -Default $null

        $subnets = @(Get-MtAzProperty -InputObject $properties -Name 'subnets' -Default @())
        $interfaces = @(Get-MtAzProperty -InputObject $properties -Name 'networkInterfaces' -Default @())

        if ($subnets.Count -eq 0 -and $interfaces.Count -eq 0) {
            $null = $unattachedNsgs.Add([pscustomobject]@{
                    Name          = $nsgName
                    Id            = $nsgId
                    ResourceGroup = (Get-MtAzResourceGroupName -ResourceId $nsgId)
                })
        }

        foreach ($rule in @(Get-MtAzProperty -InputObject $properties -Name 'securityRules' -Default @())) {
            $ruleProperties = Get-MtAzProperty -InputObject $rule -Name 'properties' -Default $null

            $direction = [string](Get-MtAzProperty -InputObject $ruleProperties -Name 'direction' -Default '')
            $access = [string](Get-MtAzProperty -InputObject $ruleProperties -Name 'access' -Default '')

            if ($direction -ne 'Inbound' -or $access -ne 'Allow') {
                continue
            }

            $sources = New-Object System.Collections.ArrayList
            $single = [string](Get-MtAzProperty -InputObject $ruleProperties -Name 'sourceAddressPrefix' -Default '')
            if (-not [string]::IsNullOrWhiteSpace($single)) {
                $null = $sources.Add($single)
            }
            foreach ($prefix in @(Get-MtAzProperty -InputObject $ruleProperties -Name 'sourceAddressPrefixes' -Default @())) {
                $null = $sources.Add([string]$prefix)
            }

            $internetFacing = $false
            foreach ($source in $sources) {
                if (Test-MtInternetSource -Prefix $source) {
                    $internetFacing = $true
                    break
                }
            }

            if (-not $internetFacing) {
                continue
            }

            $portExpressions = New-Object System.Collections.ArrayList
            $singlePort = [string](Get-MtAzProperty -InputObject $ruleProperties -Name 'destinationPortRange' -Default '')
            if (-not [string]::IsNullOrWhiteSpace($singlePort)) {
                $null = $portExpressions.Add($singlePort)
            }
            foreach ($range in @(Get-MtAzProperty -InputObject $ruleProperties -Name 'destinationPortRanges' -Default @())) {
                $null = $portExpressions.Add([string]$range)
            }

            $exposedPorts = New-Object System.Collections.ArrayList
            foreach ($expression in $portExpressions) {
                foreach ($port in (Expand-MtPortRange -PortExpression $expression)) {
                    if (-not $exposedPorts.Contains($port)) {
                        $null = $exposedPorts.Add($port)
                    }
                }
            }

            $null = $exposures.Add([pscustomobject]@{
                    NsgName       = $nsgName
                    NsgId         = $nsgId
                    ResourceGroup = (Get-MtAzResourceGroupName -ResourceId $nsgId)
                    RuleName      = [string](Get-MtAzProperty -InputObject $rule -Name 'name' -Default '')
                    Priority      = (Get-MtAzProperty -InputObject $ruleProperties -Name 'priority' -Default $null)
                    Protocol      = [string](Get-MtAzProperty -InputObject $ruleProperties -Name 'protocol' -Default '')
                    Sources       = @($sources)
                    PortExpressions = @($portExpressions)
                    ExposedPorts  = @($exposedPorts)
                    Attached      = (($subnets.Count + $interfaces.Count) -gt 0)
                })
        }
    }

    $orphanedIps = New-Object System.Collections.ArrayList
    foreach ($ip in $publicIps.Items) {
        $properties = Get-MtAzProperty -InputObject $ip -Name 'properties' -Default $null
        $configuration = Get-MtAzProperty -InputObject $properties -Name 'ipConfiguration' -Default $null

        if ($null -eq $configuration) {
            $null = $orphanedIps.Add([pscustomobject]@{
                    Name          = [string](Get-MtAzProperty -InputObject $ip -Name 'name' -Default '')
                    Id            = [string](Get-MtAzProperty -InputObject $ip -Name 'id' -Default '')
                    ResourceGroup = (Get-MtAzResourceGroupName -ResourceId ([string](Get-MtAzProperty -InputObject $ip -Name 'id' -Default '')))
                    Sku           = [string](Get-MtAzProperty -InputObject (Get-MtAzProperty -InputObject $ip -Name 'sku' -Default $null) -Name 'name' -Default '')
                })
        }
    }

    $orphanedNics = New-Object System.Collections.ArrayList
    foreach ($nic in $nics.Items) {
        $properties = Get-MtAzProperty -InputObject $nic -Name 'properties' -Default $null
        $vm = Get-MtAzProperty -InputObject $properties -Name 'virtualMachine' -Default $null

        if ($null -eq $vm) {
            $null = $orphanedNics.Add([pscustomobject]@{
                    Name          = [string](Get-MtAzProperty -InputObject $nic -Name 'name' -Default '')
                    Id            = [string](Get-MtAzProperty -InputObject $nic -Name 'id' -Default '')
                    ResourceGroup = (Get-MtAzResourceGroupName -ResourceId ([string](Get-MtAzProperty -InputObject $nic -Name 'id' -Default '')))
                })
        }
    }

    return [pscustomobject]@{
        Exposures      = @($exposures)
        UnattachedNsgs = @($unattachedNsgs)
        OrphanedIps    = @($orphanedIps)
        OrphanedNics   = @($orphanedNics)
        NsgCount       = @($nsgs.Items).Count
        Denied         = ($nsgs.Denied -or $publicIps.Denied -or $nics.Denied)
        Message        = $nsgs.Message
    }
}

function Get-MtAzureStorageAccount {
    <#
    .SYNOPSIS
        Storage accounts with their transport and access posture flattened.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $uri = 'subscriptions/{0}/providers/Microsoft.Storage/storageAccounts' -f $SubscriptionId
    $result = Invoke-MtAzRequest -Context $Context -Uri $uri -ApiVersion (Get-MtAzApiVersion -Provider 'storage')

    $accounts = New-Object System.Collections.ArrayList
    foreach ($account in $result.Items) {
        $properties = Get-MtAzProperty -InputObject $account -Name 'properties' -Default $null
        $networkAcls = Get-MtAzProperty -InputObject $properties -Name 'networkAcls' -Default $null
        $id = [string](Get-MtAzProperty -InputObject $account -Name 'id' -Default '')

        $null = $accounts.Add([pscustomobject]@{
                Name                 = [string](Get-MtAzProperty -InputObject $account -Name 'name' -Default '')
                Id                   = $id
                ResourceGroup        = (Get-MtAzResourceGroupName -ResourceId $id)
                Location             = [string](Get-MtAzProperty -InputObject $account -Name 'location' -Default '')
                AllowBlobPublicAccess = [bool](Get-MtAzProperty -InputObject $properties -Name 'allowBlobPublicAccess' -Default $false)
                HttpsOnly            = [bool](Get-MtAzProperty -InputObject $properties -Name 'supportsHttpsTrafficOnly' -Default $true)
                MinimumTlsVersion    = [string](Get-MtAzProperty -InputObject $properties -Name 'minimumTlsVersion' -Default '')
                AllowSharedKeyAccess = [bool](Get-MtAzProperty -InputObject $properties -Name 'allowSharedKeyAccess' -Default $true)
                NetworkDefaultAction = [string](Get-MtAzProperty -InputObject $networkAcls -Name 'defaultAction' -Default '')
                Raw                  = $account
            })
    }

    return [pscustomobject]@{
        Accounts = @($accounts)
        Denied   = $result.Denied
        Message  = $result.Message
    }
}

function Get-MtAzureComputeHygiene {
    <#
    .SYNOPSIS
        Virtual machines, unattached disks, and backup coverage.

    .DESCRIPTION
        Backup coverage is derived by listing protected items across Recovery
        Services vaults and matching on the VM resource id. A subscription with
        no vaults returns every VM as unprotected, which is correct rather than
        a false positive.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $computeVersion = Get-MtAzApiVersion -Provider 'compute'
    $base = 'subscriptions/{0}/providers/Microsoft.Compute' -f $SubscriptionId

    $vms = Invoke-MtAzRequest -Context $Context -Uri ('{0}/virtualMachines' -f $base) -ApiVersion $computeVersion
    $disks = Invoke-MtAzRequest -Context $Context -Uri ('{0}/disks' -f $base) -ApiVersion $computeVersion

    $vaultUri = 'subscriptions/{0}/providers/Microsoft.RecoveryServices/vaults' -f $SubscriptionId
    $vaults = Invoke-MtAzRequest -Context $Context -Uri $vaultUri -ApiVersion (Get-MtAzApiVersion -Provider 'recoveryServices')

    $protectedIds = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $backupReadable = $true

    foreach ($vault in $vaults.Items) {
        $vaultId = [string](Get-MtAzProperty -InputObject $vault -Name 'id' -Default '')
        if ([string]::IsNullOrWhiteSpace($vaultId)) {
            continue
        }

        $itemsUri = '{0}/backupProtectedItems' -f $vaultId.TrimStart('/')
        $items = Invoke-MtAzRequest -Context $Context -Uri $itemsUri -ApiVersion (Get-MtAzApiVersion -Provider 'recoveryServices')

        if (-not $items.Success) {
            $backupReadable = $false
            continue
        }

        foreach ($item in $items.Items) {
            $properties = Get-MtAzProperty -InputObject $item -Name 'properties' -Default $null
            $sourceId = [string](Get-MtAzProperty -InputObject $properties -Name 'sourceResourceId' -Default '')
            if (-not [string]::IsNullOrWhiteSpace($sourceId)) {
                $null = $protectedIds.Add($sourceId)
            }
        }
    }

    $machines = New-Object System.Collections.ArrayList
    foreach ($vm in $vms.Items) {
        $id = [string](Get-MtAzProperty -InputObject $vm -Name 'id' -Default '')
        $null = $machines.Add([pscustomobject]@{
                Name          = [string](Get-MtAzProperty -InputObject $vm -Name 'name' -Default '')
                Id            = $id
                ResourceGroup = (Get-MtAzResourceGroupName -ResourceId $id)
                Location      = [string](Get-MtAzProperty -InputObject $vm -Name 'location' -Default '')
                BackedUp      = $protectedIds.Contains($id)
            })
    }

    $unattachedDisks = New-Object System.Collections.ArrayList
    foreach ($disk in $disks.Items) {
        $properties = Get-MtAzProperty -InputObject $disk -Name 'properties' -Default $null
        $state = [string](Get-MtAzProperty -InputObject $properties -Name 'diskState' -Default '')

        if ($state -eq 'Unattached') {
            $id = [string](Get-MtAzProperty -InputObject $disk -Name 'id' -Default '')
            $null = $unattachedDisks.Add([pscustomobject]@{
                    Name          = [string](Get-MtAzProperty -InputObject $disk -Name 'name' -Default '')
                    Id            = $id
                    ResourceGroup = (Get-MtAzResourceGroupName -ResourceId $id)
                    SizeGb        = (Get-MtAzProperty -InputObject $properties -Name 'diskSizeGB' -Default $null)
                })
        }
    }

    return [pscustomobject]@{
        VirtualMachines = @($machines)
        UnattachedDisks = @($unattachedDisks)
        VaultCount      = @($vaults.Items).Count
        BackupReadable  = $backupReadable
        Denied          = ($vms.Denied -or $disks.Denied)
        Message         = $vms.Message
    }
}

function Get-MtAzurePolicyState {
    <#
    .SYNOPSIS
        Policy assignments and non-compliant resource counts.

    .DESCRIPTION
        Policy Insights is frequently denied to a plain Contributor. The result
        reports that rather than an empty compliant state, because "no findings"
        and "could not look" must never render the same way.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $assignmentUri = 'subscriptions/{0}/providers/Microsoft.Authorization/policyAssignments' -f $SubscriptionId
    $assignments = Invoke-MtAzRequest -Context $Context -Uri $assignmentUri -ApiVersion (Get-MtAzApiVersion -Provider 'policyAssignments')

    $summaryUri = 'subscriptions/{0}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize' -f $SubscriptionId
    # policyStates/latest/summarize is POST-only in ARM despite being a pure
    # read, so it needs the ReadOnlyPost escape or the write gate refuses it.
    $summary = Invoke-MtAzRequest -Context $Context -Uri $summaryUri -Method 'POST' -ReadOnlyPost `
        -ApiVersion (Get-MtAzApiVersion -Provider 'policyStates')

    $nonCompliant = 0
    if ($summary.Success -and @($summary.Items).Count -gt 0) {
        $first = @($summary.Items)[0]
        $results = Get-MtAzProperty -InputObject $first -Name 'results' -Default $null
        $nonCompliant = [int](Get-MtAzProperty -InputObject $results -Name 'nonCompliantResources' -Default 0)
    }

    return [pscustomobject]@{
        AssignmentCount       = @($assignments.Items).Count
        Assignments           = @($assignments.Items)
        NonCompliantResources = $nonCompliant
        SummaryReadable       = $summary.Success
        Denied                = ($assignments.Denied -or $summary.Denied)
        Message               = $summary.Message
    }
}

function Get-MtAzureMonitoring {
    <#
    .SYNOPSIS
        Log Analytics workspaces, alert rules and action groups.

    .DESCRIPTION
        An alert rule with no action group fires into the void. So does an
        action group with no receivers. Both look healthy in the portal.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $workspaceUri = 'subscriptions/{0}/providers/Microsoft.OperationalInsights/workspaces' -f $SubscriptionId
    $workspaces = Invoke-MtAzRequest -Context $Context -Uri $workspaceUri -ApiVersion (Get-MtAzApiVersion -Provider 'operationalInsights')

    $alertUri = 'subscriptions/{0}/providers/Microsoft.Insights/metricAlerts' -f $SubscriptionId
    $alerts = Invoke-MtAzRequest -Context $Context -Uri $alertUri -ApiVersion (Get-MtAzApiVersion -Provider 'insights')

    $actionUri = 'subscriptions/{0}/providers/Microsoft.Insights/actionGroups' -f $SubscriptionId
    $actionGroups = Invoke-MtAzRequest -Context $Context -Uri $actionUri -ApiVersion (Get-MtAzApiVersion -Provider 'actionGroups')

    $workspaceRows = New-Object System.Collections.ArrayList
    foreach ($workspace in $workspaces.Items) {
        $properties = Get-MtAzProperty -InputObject $workspace -Name 'properties' -Default $null
        $null = $workspaceRows.Add([pscustomobject]@{
                Name           = [string](Get-MtAzProperty -InputObject $workspace -Name 'name' -Default '')
                Id             = [string](Get-MtAzProperty -InputObject $workspace -Name 'id' -Default '')
                RetentionDays  = [int](Get-MtAzProperty -InputObject $properties -Name 'retentionInDays' -Default 0)
                Sku            = [string](Get-MtAzProperty -InputObject (Get-MtAzProperty -InputObject $properties -Name 'sku' -Default $null) -Name 'name' -Default '')
            })
    }

    $alertRows = New-Object System.Collections.ArrayList
    foreach ($alert in $alerts.Items) {
        $properties = Get-MtAzProperty -InputObject $alert -Name 'properties' -Default $null
        $actions = @(Get-MtAzProperty -InputObject $properties -Name 'actions' -Default @())

        $null = $alertRows.Add([pscustomobject]@{
                Name        = [string](Get-MtAzProperty -InputObject $alert -Name 'name' -Default '')
                Id          = [string](Get-MtAzProperty -InputObject $alert -Name 'id' -Default '')
                Enabled     = [bool](Get-MtAzProperty -InputObject $properties -Name 'enabled' -Default $true)
                ActionCount = $actions.Count
            })
    }

    $actionRows = New-Object System.Collections.ArrayList
    foreach ($group in $actionGroups.Items) {
        $properties = Get-MtAzProperty -InputObject $group -Name 'properties' -Default $null

        $receiverCount = 0
        foreach ($field in @('emailReceivers', 'smsReceivers', 'webhookReceivers', 'azureAppPushReceivers', 'voiceReceivers', 'logicAppReceivers', 'azureFunctionReceivers', 'eventHubReceivers')) {
            $receiverCount = $receiverCount + @(Get-MtAzProperty -InputObject $properties -Name $field -Default @()).Count
        }

        $null = $actionRows.Add([pscustomobject]@{
                Name          = [string](Get-MtAzProperty -InputObject $group -Name 'name' -Default '')
                Id            = [string](Get-MtAzProperty -InputObject $group -Name 'id' -Default '')
                Enabled       = [bool](Get-MtAzProperty -InputObject $properties -Name 'enabled' -Default $true)
                ReceiverCount = $receiverCount
            })
    }

    return [pscustomobject]@{
        Workspaces   = @($workspaceRows)
        AlertRules   = @($alertRows)
        ActionGroups = @($actionRows)
        Denied       = ($workspaces.Denied -or $alerts.Denied -or $actionGroups.Denied)
        Message      = $workspaces.Message
    }
}
