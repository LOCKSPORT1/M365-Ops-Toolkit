# M365 Operations Toolkit

Multi-tenant Microsoft 365 and Azure operations tooling in PowerShell, with the
runbooks that go around it.

No module dependencies. No Graph SDK. Windows PowerShell 5.1 and PowerShell 7,
on Windows, Linux and macOS — so the same code runs on an admin workstation, in
an Azure Automation sandbox, and under an RMM runner as SYSTEM without an
install step.

## See it run in ninety seconds

```powershell
git clone https://github.com/LOCKSPORT1/<repo>.git
cd <repo>
.\MtDemo\Invoke-Demo.ps1
```

Offline. No tenant, no network, no local server, no elevation. HTTP responses
come from recorded fixtures; every layer above the transport is real module
code — token handling, retry, paging, the write gate, both findings engines,
both report writers.

Add `-Pause` to step through it during a screen-share.

**Windows:** scripts extracted from a downloaded archive carry the mark-of-the-web and will not run. Clear it once with `Get-ChildItem -Recurse | Unblock-File`, or allow a single session with `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

## What is here

| Component | What it does |
| --- | --- |
| **[MtGraph](MtGraph/)** | The engine. Tenant context model, token acquisition (certificate / client secret / device code), resilient request pipeline with paging and throttling, read-only write gating, structured run artifacts. Graph and Azure Resource Manager. |
| **[MtContainment](MtContainment/)** | Account compromise investigation and containment. Read-only evidence collection, prioritized findings, gated containment sequenced in the order that actually works. |
| **[MtAzurePosture](MtAzurePosture/)** | Read-only Azure governance, network, storage, resilience and monitoring sweep across subscriptions. |
| **[MtDemo](MtDemo/)** | The offline walkthrough above. |
| **[Runbooks](Runbooks/)** | Business email compromise response, user offboarding, new client tenant onboarding. |

```
MtGraph                      foundation, zero dependencies
   |
   +-- MtContainment         M365 account compromise
   +-- MtAzurePosture        Azure governance sweep
            |
        MtDemo               needs all three
        Runbooks             reference all three, depend on none
```

MtContainment and MtAzurePosture do not know about each other. Either works with
MtGraph alone.

## Why it exists

*Tenant-neutral* means a script has no hardcoded values and works in whichever
tenant you are signed into. That is not enough for managed services.
*Multi-tenant* means one run, N customers, delegated access, per-customer
capability differences, and a failure in one customer that does not abort the
other forty.

That difference is an object model, not a coding style, so it belongs in the
core rather than in each tool.

## Five conventions

Anything built here inherits these, and they are what make it a toolkit rather
than three scripts in a folder.

**Engine and UI are separate.** Every function returns objects and never writes
to the host. A GUI would bind to the same functions a scheduled runbook calls.

**Read-only by default.** A new context refuses POST, PATCH, PUT and DELETE. The
intended call is logged and a simulation object returned, so calling code is
written once and runs in both modes. The gate lives in the request pipeline, so
a tool cannot forget to honour it. Arming is explicit and per-context — a fleet
run can be read-only everywhere except the one tenant you intend to change.

**Capability, not assumption.** Licensing is discovered from `subscribedSkus`
and tools branch on it. Calling a Purview endpoint on a tenant with no Purview
plan returns a confusing 403, not "not licensed".

**Every run emits an artifact.** `Start-MtRun` opens a folder, `Write-MtLog`
appends structured JSONL, `Complete-MtRun` writes `summary.json` for machines and
`summary.md` for the ticket. Mutations log at level `Change`, refusals at
`WhatIf`, kept distinct so the summary is honest about what was touched.

**Coverage gaps are first-class.** Every collector reports what it could not
read. A gap you disclose is evidence; a gap you leave silent is a false
all-clear. Graph does not expose mailbox-level SMTP forwarding, so every
containment report says so and gives the Exchange cmdlet that closes it.

## Getting started

```powershell
# MtGraph first: the others declare it as a required module.
Import-Module .\MtGraph\MtGraph.psd1
Import-Module .\MtContainment\MtContainment.psd1
Import-Module .\MtAzurePosture\MtAzurePosture.psd1

# Delegated sign-in: the token can never exceed what you can already do.
$ctx = New-MtTenantContext -TenantId '<tenant>' -ClientId $appId -DeviceCode |
    Connect-MtTenant

# Read-only investigation
$investigation = Get-MtUserInvestigation -Context $ctx -User '<upn>' -Days 7
Get-MtInvestigationFinding -Investigation $investigation |
    Where-Object { $_.Severity -in 'Critical', 'High' } |
    Format-Table Severity, Category, Title

# Read-only Azure sweep
$posture = Get-MtAzurePosture -Context $ctx
Get-MtAzureFinding -Posture $posture | Format-Table Severity, Category, Resource, Title
```

Import MtGraph first. The dependent manifests declare
`RequiredModules = @('MtGraph')`, which is satisfied when it is already loaded —
but importing a dependent module cold from a folder outside `$env:PSModulePath`
sends PowerShell looking for MtGraph in the Gallery and fails confusingly.

Per-module setup, permission lists and known limitations live in each module's
own README.

## Multi-tenant

```powershell
$book = Import-MtTenantConfig -Path .\MtGraph\tenants.json | Connect-MtTenant

$results = $book | Invoke-MtForEachTenant -ShowProgress -ScriptBlock {
    param($Context)
    Get-MtAzurePosture -Context $Context
}

$results | Where-Object { -not $_.Success } | Select-Object Tenant, Error
```

One customer's expired secret, revoked consent or throttled tenant produces a
failed result object with its stack trace captured. It does not abort the rest.

Copy `MtGraph/tenants.sample.json` to `tenants.json` and keep that file out of
source control — it is gitignored. No secrets belong in it: certificate auth
reads a thumbprint from the local store, client secret auth reads a named
environment variable.

## Testing

Each module ships a test double and an integration test. Python 3 runs the
doubles; the demo needs neither.

```bash
# MtGraph
python3 MtGraph/Tests/Start-FakeGraph.py &
pwsh -File MtGraph/Tests/Invoke-IntegrationTest.ps1

# MtContainment
python3 MtContainment/Tests/Start-FakeM365.py &
pwsh -File MtContainment/Tests/Invoke-IntegrationTest.ps1

# MtAzurePosture
python3 MtAzurePosture/Tests/Start-FakeArm.py &
pwsh -File MtAzurePosture/Tests/Invoke-IntegrationTest.ps1

# Parse gate across every file
pwsh -File MtGraph/Tests/Invoke-ParseCheck.ps1
```

The doubles return real 429s with `Retry-After`, real `@odata.nextLink` paging,
real Graph and ARM error bodies, and a deliberately denied scope. They are how
the retry policy, the write gate and the coverage-gap reporting get verified
without a tenant — and they are how several real bugs were caught, including a
strict-mode failure on empty JSON objects and `Retry-After` being silently
ignored on PowerShell 7's error path.

## Known limitations

- **Mailbox-level SMTP forwarding** is not exposed by Graph. Reported as a gap
  on every containment run, with the Exchange cmdlet to check it.
- **No message trace or quarantine.** Those live in Exchange Online and the
  security and compliance endpoints. A second transport is needed.
- **ARM API versions are pinned** in one table per resource provider. They were
  current at authoring; verify before relying on a new one.
- **GDAP consent mechanics** have changed more than once. Verify the current
  flow against Microsoft's documentation before standing this up against
  production customers.
- **Defender and Purview are not covered.** Neither is referenced anywhere in
  this toolkit.

## See also

**[M365GovGuard](https://github.com/LOCKSPORT1/M365GovGuard)** — posture assessment and remediation for Microsoft 365 Commercial, GCC, GCC High and DoD tenants. Same conventions: read-only by default, capability-gated, self-documenting runs.

## License

MIT. See [LICENSE](LICENSE).
