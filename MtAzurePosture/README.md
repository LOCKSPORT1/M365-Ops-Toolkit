# MtAzurePosture

Read-only Azure governance, network, storage, resilience and monitoring sweep
across subscriptions. Built on [MtGraph](../MtGraph).

**Every call is a GET** (with one documented exception below). Nothing in this
module mutates anything, and no write permission is required to run it. That is
the point: an engineer holding Contributor — or even Reader — can produce the
whole report without asking for elevated access first.

## What it checks

| Area | Checks |
| --- | --- |
| **Network** | NSG rules allowing the internet inbound to management and database ports; NSGs attached to nothing; orphaned public IPs and NICs |
| **Storage** | anonymous blob access, HTTP allowed, TLS below 1.2, firewall default action Allow |
| **Identity** | user principals holding Owner at subscription scope; classic administrators still assigned |
| **Resilience** | VMs with no Recovery Services backup protection; unattached managed disks |
| **Governance** | Policy assignments present; non-compliant resource count |
| **Monitoring** | alert rules with no action group; action groups with no receivers; Log Analytics retention below 90 days |

The network check is the highest-value read here. Internet-facing RDP or SQL is
the most commonly exploited Azure misconfiguration and is trivially findable if
anyone looks.

Port ranges are expanded, not string-matched. A rule allowing `1000-4000` is
exactly as exposed as one naming `3389`, and far easier to miss by eye — the
sweep reports both, and correctly ignores a rule that only opens 443.

## Three things that make it honest

**A denied scope is a gap, not a clean result.** Contributor cannot read Policy
Insights, and some scopes deny role definitions or Recovery Services. Every
collector records what it could not read, and the report says so. "No findings"
and "could not look" must never render the same way.

**Role GUIDs degrade gracefully.** If role definitions cannot be read,
assignments are reported by GUID rather than silently dropped, with a coverage
gap noting why the names are missing.

**Backup state is derived, not assumed.** Protected items are listed across
Recovery Services vaults and matched on VM resource id. A subscription with no
vaults reports every VM unprotected — which is correct, not a false positive.

## API versions

ARM has no tenant-wide API version: every resource provider versions
independently, and a wrong version is a 400 rather than a soft failure. They are
pinned in one table in `Get-MtAzApiVersion`, so when a provider moves, one line
changes rather than a grep across the module.

Those versions were current at authoring. Verify against provider docs before
relying on a new one.

## The one POST

`policyStates/latest/summarize` is POST-only in ARM despite being a pure read.
A write gate keyed on HTTP verb refuses it, which would make a read-only sweep
unable to read — so MtGraph gained a deliberately narrow `-ReadOnlyPost` switch
that treats a POST as non-mutating for gating purposes.

Pass it only where the endpoint genuinely cannot change state. Other members of
that family: Resource Graph queries, and Graph's `getMemberGroups`. Anything it
unlocks still appears in the run log.

## Usage

```powershell
Import-Module .\MtGraph\MtGraph.psd1
Import-Module .\MtAzurePosture\MtAzurePosture.psd1

# Delegated sign-in: the token can never exceed what you can already do.
$ctx = New-MtTenantContext -TenantId '<tenant id>' -ClientId $appId -DeviceCode |
    Connect-MtTenant

$run = Start-MtRun -Name 'AzurePostureSweep' -Context @($ctx) -Ticket 'PROJ-118'

$posture = Get-MtAzurePosture -Context $ctx
Get-MtAzureFinding -Posture $posture |
    Where-Object { $_.Severity -in 'Critical', 'High' } |
    Format-Table Severity, Category, Resource, Title

Export-MtAzureReport -Posture $posture -Path $run.Path -Ticket 'PROJ-118'
Complete-MtRun -Run $run -Outcome 'Completed'
```

Scope to specific subscriptions with `-SubscriptionId`. Across a whole customer
book, wrap it in `Invoke-MtForEachTenant` so one denied tenant does not abort
the rest.

## Permissions

**Reader at subscription scope** covers most of it. For full coverage add:

- `Microsoft.Authorization/roleDefinitions/read` — role names instead of GUIDs
- `Microsoft.PolicyInsights/policyStates/read` — compliance summary
- `Microsoft.RecoveryServices/vaults/backupProtectedItems/read` — backup coverage

Contributor is missing some of these in practice. The sweep runs anyway and
reports the gaps.

## Multi-audience tokens

Graph and ARM are different audiences: a token minted for `graph.microsoft.com`
is rejected by `management.azure.com`. MtGraph's context therefore caches one
token per service rather than one overall, selected with `-Service Graph` or
`-Service ResourceManager`.

In the delegated flows a refresh token is not audience-bound, so a session that
already signed in for Graph gets its ARM token silently — one prompt per
session, not one per service.

## Tests

```bash
python3 Tests/Start-FakeArm.py &      # 127.0.0.1:8098
pwsh -File Tests/Invoke-IntegrationTest.ps1
```

The test double stages a deliberately imperfect estate: internet-facing RDP on
an attached NSG, a `1000-4000` range hiding SQL on an unattached one, a legacy
storage account with four problems and a clean one beside it, an unbacked VM
next to a protected one, orphaned disk/IP/NIC, two user Owners plus a classic
admin, an alert rule with no action group, an action group with no receivers,
30-day Log Analytics retention, and Policy Insights returning 403.

Verified on PowerShell 7.4:

- 18 findings: 1 Critical, 4 High, 6 Medium
- the `1000-4000` range correctly expands to 1433, 1521, 3306, 3389
- a rule opening only 443 produces no finding
- the clean storage account produces **zero** findings
- the denied Policy scope becomes a reported coverage gap, not a clean pass
- the sweep records **zero** changes and zero simulated writes
- ARM requests without `-ApiVersion` are rejected with a clear message
- the token cache holds separate Graph and ResourceManager slots

## License

MIT.
