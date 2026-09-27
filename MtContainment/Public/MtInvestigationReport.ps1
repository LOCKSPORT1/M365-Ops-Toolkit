function Export-MtInvestigationReport {
    <#
    .SYNOPSIS
        Writes an incident report from an investigation, with optional
        containment results appended.

    .DESCRIPTION
        Produces three files: investigation.json (full evidence, machine
        readable), findings.json, and report.md -- the part that goes in the
        ticket.

        The report always states what was NOT checked. A coverage gap you
        disclose is evidence; a gap you leave silent is a false all-clear.

    .EXAMPLE
        Export-MtInvestigationReport -Investigation $investigation -Path .\INC-4471

    .EXAMPLE
        Export-MtInvestigationReport -Investigation $investigation -Containment $result -Path $run.Path
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Investigation,

        [AllowNull()]
        [object]$Containment = $null,

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
            $Finding = @(Get-MtInvestigationFinding -Investigation $Investigation)
        }

        $investigationPath = Join-Path -Path $Path -ChildPath 'investigation.json'
        $findingsPath = Join-Path -Path $Path -ChildPath 'findings.json'
        $reportPath = Join-Path -Path $Path -ChildPath 'report.md'

        $Investigation | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $investigationPath -Encoding UTF8
        @($Finding) | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $findingsPath -Encoding UTF8

        $account = $Investigation.Account
        $markdown = New-Object System.Text.StringBuilder

        $null = $markdown.AppendLine(('# Account investigation: {0}' -f $Investigation.UserPrincipalName))
        $null = $markdown.AppendLine('')
        if (-not [string]::IsNullOrWhiteSpace($Ticket)) {
            $null = $markdown.AppendLine(('- **Ticket:** {0}' -f $Ticket))
        }
        $null = $markdown.AppendLine(('- **Tenant:** {0}' -f $Investigation.Tenant))
        $null = $markdown.AppendLine(('- **User:** {0} ({1})' -f [string](Get-MtContainmentProperty -InputObject $account -Name 'displayName' -Default ''), $Investigation.UserPrincipalName))
        $null = $markdown.AppendLine(('- **Object id:** {0}' -f $Investigation.UserId))
        $null = $markdown.AppendLine(('- **Collected (UTC):** {0}' -f (Format-MtTimestamp -Value $Investigation.CollectedOn)))
        $null = $markdown.AppendLine(('- **Lookback:** {0} day(s)' -f $Investigation.LookbackDays))
        $null = $markdown.AppendLine(('- **Account enabled:** {0}' -f [string](Get-MtContainmentProperty -InputObject $account -Name 'accountEnabled' -Default '')))
        $null = $markdown.AppendLine(('- **Last password change:** {0} UTC' -f (Format-MtTimestamp -Value (Get-MtContainmentProperty -InputObject $account -Name 'lastPasswordChangeDateTime' -Default $null))))
        $null = $markdown.AppendLine(('- **Synced from on-premises AD:** {0}' -f [string](Get-MtContainmentProperty -InputObject $account -Name 'onPremisesSyncEnabled' -Default 'false')))
        $null = $markdown.AppendLine('')

        # ---- Summary counts ----
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

        # ---- Findings ----
        $actionable = @($Finding | Where-Object { @('Critical', 'High', 'Medium') -contains $_.Severity })

        if ($actionable.Count -gt 0) {
            $null = $markdown.AppendLine('## Findings')
            $null = $markdown.AppendLine('')
            foreach ($item in $actionable) {
                $null = $markdown.AppendLine(('### [{0}] {1}' -f $item.Severity, $item.Title))
                $null = $markdown.AppendLine('')
                $null = $markdown.AppendLine(('*{0}*' -f $item.Category))
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
        else {
            $null = $markdown.AppendLine('## Findings')
            $null = $markdown.AppendLine('')
            $null = $markdown.AppendLine('No Critical, High or Medium findings. See the coverage gaps below before treating this as an all-clear.')
            $null = $markdown.AppendLine('')
        }

        # ---- Evidence tables ----
        $rules = @($Investigation.InboxRules)
        if ($rules.Count -gt 0) {
            $null = $markdown.AppendLine('## Inbox rules')
            $null = $markdown.AppendLine('')
            $null = $markdown.AppendLine('| Rule | Enabled | External recipients | Moves to | Deletes |')
            $null = $markdown.AppendLine('| --- | --- | --- | --- | --- |')
            foreach ($rule in $rules) {
                $null = $markdown.AppendLine(('| {0} | {1} | {2} | {3} | {4} |' -f `
                            $rule.DisplayName, $rule.IsEnabled, ((@($rule.ExternalRecipients) -join ', ')), $rule.MoveToFolderName, ($rule.Deletes -or $rule.PermanentDeletes)))
            }
            $null = $markdown.AppendLine('')
        }

        $grants = @($Investigation.OAuthGrants)
        if ($grants.Count -gt 0) {
            $null = $markdown.AppendLine('## OAuth grants')
            $null = $markdown.AppendLine('')
            $null = $markdown.AppendLine('| Application | Verified publisher | Highest risk | Sensitive scopes |')
            $null = $markdown.AppendLine('| --- | --- | --- | --- |')
            foreach ($grant in $grants) {
                $null = $markdown.AppendLine(('| {0} | {1} | {2} | {3} |' -f $grant.Application, $grant.VerifiedPublisher, $grant.HighestRisk, ((@($grant.RiskyScopes) -join ', '))))
            }
            $null = $markdown.AppendLine('')
        }

        $methods = @($Investigation.AuthMethods)
        if ($methods.Count -gt 0) {
            $null = $markdown.AppendLine('## Registered authentication methods')
            $null = $markdown.AppendLine('')
            $null = $markdown.AppendLine('| Type | Detail | Registered |')
            $null = $markdown.AppendLine('| --- | --- | --- |')
            foreach ($method in $methods) {
                $detail = $method.DisplayName
                if ([string]::IsNullOrWhiteSpace($detail)) {
                    $detail = $method.PhoneNumber
                }
                if ([string]::IsNullOrWhiteSpace($detail)) {
                    $detail = $method.EmailAddress
                }
                $null = $markdown.AppendLine(('| {0} | {1} | {2} |' -f $method.Type, $detail, (Format-MtTimestamp -Value $method.CreatedOn)))
            }
            $null = $markdown.AppendLine('')
        }

        # ---- Containment ----
        if ($null -ne $Containment) {
            $null = $markdown.AppendLine('## Containment')
            $null = $markdown.AppendLine('')
            $null = $markdown.AppendLine(('- **Scope:** {0}' -f $Containment.Scope))
            $null = $markdown.AppendLine(('- **Mode:** {0}' -f $Containment.Mode))
            $null = $markdown.AppendLine(('- **Applied:** {0}  **Simulated:** {1}' -f $Containment.AppliedCount, $Containment.SimulatedCount))
            $null = $markdown.AppendLine('')
            $null = $markdown.AppendLine('| Action | Target | Result | Note |')
            $null = $markdown.AppendLine('| --- | --- | --- | --- |')
            foreach ($action in @($Containment.Actions)) {
                $state = 'applied'
                if ($action.Simulated) {
                    $state = 'simulated'
                }
                elseif (-not $action.Success) {
                    $state = 'skipped'
                }
                $null = $markdown.AppendLine(('| {0} | {1} | {2} | {3} |' -f $action.Action, $action.Target, $state, $action.Message))
            }
            $null = $markdown.AppendLine('')
        }

        # ---- Coverage ----
        $gaps = @($Investigation.NotChecked)
        if ($gaps.Count -gt 0) {
            $null = $markdown.AppendLine('## Not checked')
            $null = $markdown.AppendLine('')
            foreach ($gap in $gaps) {
                $null = $markdown.AppendLine(('- **{0}** — {1}' -f $gap.Source, $gap.Reason))
            }
            $null = $markdown.AppendLine('')
        }

        $errors = @($Investigation.Errors)
        if ($errors.Count -gt 0) {
            $null = $markdown.AppendLine('## Collection errors')
            $null = $markdown.AppendLine('')
            foreach ($item in $errors) {
                $null = $markdown.AppendLine(('- **{0}** — {1}' -f $item.Source, $item.Message))
            }
            $null = $markdown.AppendLine('')
        }

        $markdown.ToString() | Set-Content -LiteralPath $reportPath -Encoding UTF8

        return [pscustomobject]@{
            ReportPath        = $reportPath
            InvestigationPath = $investigationPath
            FindingsPath      = $findingsPath
        }
    }
}
