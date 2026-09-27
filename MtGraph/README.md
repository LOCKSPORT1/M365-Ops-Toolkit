# MtGraph

Multi-tenant Microsoft Graph core for PowerShell. The engine layer that tools,
runbooks and a GUI all sit on top of.

No module dependencies. No Graph SDK. Runs on Windows PowerShell 5.1 and
PowerShell 7 on Windows, Linux and macOS, which means the same code works on an
admin workstation, in an Azure Automation sandbox, and under an RMM runner as
SYSTEM without an install step.

## Why this exists

*Tenant-neutral* means a script has no hardcoded values and works in whichever
tenant you happen to be signed into. That is not enough for managed services.
*Multi-tenant* means one run, N customers, delegated access, per-customer
capability differences, and failure in one customer that does not abort the
other forty.

That difference is an object model, not a coding style, so it belongs in the
core rather than in each tool.

## Design contract

Anything built on this module inherits four rules.

**Engine and UI are separate.** Every function here returns objects and never
writes to the host. A WPF front end binds to the same functions a scheduled
runbook calls. One codebase, three entry points.

**Read-only by default.** A new context refuses `POST`, `PATCH`, `PUT` and
`DELETE`. The intended call is logged and a simulation object is returned, so
calling code is written once and runs in both modes. Arming is explicit and
per-context, via `-AllowWrites` or `Set-MtWriteMode`, so a fleet run can be
read-only everywhere except the one tenant you intend to change.

**Capability, not assumption.** `Get-MtTenantCapability` reads `subscribedSkus`
and reports what the tenant is actually licensed for. Calling a Purview endpoint
on a tenant with no Purview plan returns a confusing 403, not "not licensed".

**Every run emits an artifact.** `Start-MtRun` opens a folder, `Write-MtLog`
appends structured JSONL, `Complete-MtRun` writes `summary.json` for machines and
`summary.md` for the ticket. Mutations are logged at level `Change` and refusals
at level `WhatIf`, kept distinct so the summary is honest about what was actually
touched.

## App registration

One multi-tenant app registration in the partner tenant, consented per customer.
Certificate credentials are preferred over secrets; the certificate never leaves
the admin machine and the assertion is built and signed locally.

Application permissions for read-only inventory work:

| Permission | Used for |
| --- | --- |
| `Organization.Read.All` | tenant identity, default domain |
| `Directory.Read.All` | users, groups, roles, devices |
| `Policy.Read.All` | Conditional Access, authorization policy |
| `AuditLog.Read.All` | sign-in and directory audit logs |
| `DeviceManagementConfiguration.Read.All` | Intune configuration and compliance policies |
| `DeviceManagementManagedDevices.Read.All` | managed device inventory |
| `Reports.Read.All` | usage and service reports |

Add only as needed for write work: `User.ReadWrite.All`,
`DeviceManagementManagedDevices.PrivilegedOperations.All`,
`MailboxSettings.ReadWrite`, `Group.ReadWrite.All`.

GDAP relationship and consent mechanics have moved around more than once. Verify
the current flow against Microsoft's documentation before standing this up
against production customers.

## Quickstart

```powershell
Import-Module .\MtGraph\MtGraph.psd1

# One tenant, certificate auth, read-only
$ctx = New-MtTenantContext -TenantId 'contoso.onmicrosoft.com' `
    -ClientId '00000000-0000-0000-0000-000000000000' `
    -CertificateThumbprint 'A1B2C3D4E5F6...' `
    -Name 'Contoso Manufacturing'

$ctx = Connect-MtTenant -Context $ctx

Invoke-MtGraphRequest -Context $ctx -Uri 'users?$select=id,userPrincipalName,accountEnabled' -All |
    Where-Object { -not $_.accountEnabled }
```

```powershell
# The whole customer book, one report, failures isolated
$book = Import-MtTenantConfig -Path .\tenants.json | Connect-MtTenant

$run = Start-MtRun -Name 'CA-Policy-Inventory' -Context $book -Ticket 'PROJ-118'

$results = $book | Invoke-MtForEachTenant -ShowProgress -ScriptBlock {
    param($Context)
    Invoke-MtGraphRequest -Context $Context -Uri 'identity/conditionalAccess/policies' -All |
        Select-Object @{ n = 'Tenant'; e = { $Context.Name } }, displayName, state
}

$results | Where-Object { -not $_.Success } | Select-Object Tenant, Error
Complete-MtRun -Run $run
```

```powershell
# A write, gated
$target = Get-MtContext -Name 'Contoso Manufacturing'
Invoke-MtGraphRequest -Context $target -Method POST -Uri "users/$upn/revokeSignInSessions"
# -> returns a simulation object, logs [read-only] would POST ...

Set-MtWriteMode -Context $target -AllowWrites
Invoke-MtGraphRequest -Context $target -Method POST -Uri "users/$upn/revokeSignInSessions"
# -> executes, logs at level Change, lands in summary.md under "Changes made"
```

## Request pipeline

`Invoke-MtGraphRequest` handles the parts every Graph script eventually
reimplements badly:

- token acquisition and refresh inside a five minute skew window
- one forced token refresh on an unexpected 401 (revocation, CA change)
- retry on 429 and 5xx, honoring `Retry-After` when the service sends one,
  exponential backoff with jitter when it does not, capped at 60s
- `@odata.nextLink` paging under `-All`, with `-MaxPages` to bound it
- UTF-8 decoding from the raw stream, avoiding the charset mangling Windows
  PowerShell applies
- structured errors carrying the Graph error code and `request-id` on
  `$_.Exception.Data['MtGraph']`, so a failure in a ticket is actionable
  without a repro

## Artifact layout

```
<ArtifactRoot>/
  20260922-154301_AccountContainment_5adedc36/
    run.jsonl      # one JSON record per line: timestamp, level, tenant, message, data
    summary.json   # counters, tenants, duration, outcome
    summary.md     # the part that goes in the ticket
```

## Verified behavior

Exercised against a local Graph test double (`Tests/`) plus a live HTTPS
endpoint, on PowerShell 7.4:

- RS256 client assertion verifies against the certificate's public key
- 429 with `Retry-After: 1` waits exactly 1s, then succeeds
- two-page `@odata.nextLink` result returns all items; `-MaxPages 1` stops at one
- 403 produces `MtGraph.403.Authorization_RequestDenied` with the request id
- read-only refuses a POST and returns a simulation; armed context executes it
  and records it under "Changes made"
- a failing tenant in a fleet run is isolated, with its `ScriptStackTrace` captured
- capability discovery ignores service plans in a `Disabled` provisioning state

## Next

The tools this is meant to carry, roughly in order of value:

1. Account containment console — disable, revoke sessions, enumerate inbox rules
   and forwarding, OAuth grants, recent MFA registration, sign-in history
2. Baseline drift detector — JSON baseline, per-tenant conformance report
3. Tenant as-built exporter — regenerating documentation on a schedule
4. Joiner/mover/leaver, offboarding first
5. Triage snapshot for incoming escalations
6. Azure hygiene sweep

Then the WPF shell over the top, binding to the same functions.

## License

MIT.
