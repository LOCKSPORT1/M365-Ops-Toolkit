# MtContainment

Account compromise investigation and containment for Microsoft 365. Built on
[MtGraph](../MtGraph), so it inherits multi-tenant context, throttling, paging,
read-only gating and self-documenting run artifacts.

Two halves, deliberately separated:

**Investigate.** One read-only sweep collects every evidence source for an
account. Nothing mutates. Safe to run on a hunch, safe to hand to a junior
technician, safe to run on the wrong user by mistake.

**Contain.** Gated writes, sequenced in the order that actually works, driven
by the evidence already collected and captured in the artifact.

## Why it exists

Account containment is the most expensive thing an L2 does by hand and the most
error-prone. It spans four admin portals, the steps have to happen in a
particular order, and the two pieces everyone forgets — attacker-registered MFA
and OAuth consent — are the two that survive a password reset.

## The sequence, and why

```
1. Disable the account      fastest block on new authentication
2. Remove hostile MFA       before the reset, or the attacker self-services
                            the password back through SSPR
3. Reset the password       the credential itself
4. Revoke sessions          LAST. A token minted between a revocation and a
                            later password change survives. Revoke-then-reset
                            leaves a window open; reset-then-revoke does not.
5. Remove inbox rules       persistence and evidence destruction
6. Revoke OAuth grants      the persistence that survives steps 1 through 5
7. Confirm compromised      feed the signal back into risk-based policies
```

## What the investigation collects

| Source | Notes |
| --- | --- |
| Account attributes | enabled state, last password change, on-premises sync |
| Sign-in logs | gated on Entra ID P1 |
| Registered auth methods | with registration timestamps |
| Inbox rules | recipients classified internal vs external; `moveToFolder` ids resolved to folder names |
| OAuth grants | application resolved, publisher verified, each scope risk-rated |
| Directory roles, groups, owned objects | blast radius |
| Devices | Entra registered plus Intune managed, gated on the Intune capability |
| Directory audit | entries targeting the account, and entries it initiated |
| Identity Protection | gated on Entra ID P2 |

Each collector is wrapped independently. A missing license, a permission the app
registration never got, or a mailbox with no inbox degrades that one section
rather than failing the sweep.

**Everything not checked is reported.** A coverage gap you disclose is evidence;
a gap you leave silent is a false all-clear. Mailbox-level SMTP forwarding is
flagged every single time, because Graph does not expose
`ForwardingSmtpAddress` and the report must not imply forwarding was fully
checked:

```powershell
Get-Mailbox -Identity <upn> | Select ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
```

## Findings

`Get-MtInvestigationFinding` turns evidence into prioritized conclusions, each
with a severity, what was seen, and what to do. The rules encode the standard
BEC pattern:

- rule forwarding or redirecting outside the organization — Critical when enabled
- rule filing inbound mail into RSS Feeds, Archive, Deleted Items or similar
- rule with a blank or single-character name (`.` and a bare space are the
  classic choices, because they are easy to miss in a rule list)
- auth method registered inside the lookback window
- directory audit showing security info or password activity on the account
- delegated consent carrying mail or file scopes, escalated when the publisher
  is unverified
- successful sign-in over IMAP4, POP3, SMTP or other legacy clients
- successful sign-ins from more than one country — the cheapest impossible-travel
  check available without P2
- account holding a directory role, or owning an application object
- Identity Protection risk level

## Usage

```powershell
Import-Module .\MtGraph\MtGraph.psd1
Import-Module .\MtContainment\MtContainment.psd1

$ctx = New-MtTenantContext -TenantId 'contoso.onmicrosoft.com' -ClientId $appId `
    -CertificateThumbprint $thumbprint | Connect-MtTenant

$run = Start-MtRun -Name 'AccountContainment' -Context @($ctx) -Ticket 'INC-4471'

# Read-only. No writes are possible from this context yet.
$investigation = Get-MtUserInvestigation -Context $ctx -User 'jdoe@contoso.com' -Days 7
Get-MtInvestigationFinding -Investigation $investigation |
    Where-Object { $_.Severity -in 'Critical', 'High' } |
    Format-Table Severity, Category, Title

# Dry run: every step simulated and logged, nothing touched.
Invoke-MtAccountContainment -Context $ctx -Investigation $investigation -Scope Full

# Arm and execute.
Set-MtWriteMode -Context $ctx -AllowWrites
$result = Invoke-MtAccountContainment -Context $ctx -Investigation $investigation -Scope Full

Export-MtInvestigationReport -Investigation $investigation -Containment $result `
    -Path $run.Path -Ticket 'INC-4471'
Complete-MtRun -Run $run -Outcome 'Contained'
```

Scopes: `Standard` runs steps 1, 2, 4, 5 and 6. `Full` adds the password reset
and the Identity Protection call. `Custom` runs only the switches you pass.

## Output

```
<run>/
  report.md            the part that goes in the ticket
  investigation.json   full evidence, machine readable
  findings.json        prioritized findings
  run.jsonl            structured action log
  summary.json / .md   MtGraph run summary
```

A generated password is returned on the action result and is **never** written to
the run log — the underlying request is sent with MtGraph's `-RedactBody`.
Hand it over out of band.

## Permissions

Read-only investigation:

`User.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`,
`MailboxSettings.Read`, `Organization.Read.All`, `Domain.Read.All`,
`DeviceManagementManagedDevices.Read.All`, `IdentityRiskyUser.Read.All`,
`IdentityRiskEvent.Read.All`

Containment additionally needs:

`User.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`,
`MailboxSettings.ReadWrite`, `DelegatedPermissionGrant.ReadWrite.All`,
`IdentityRiskyUser.ReadWrite.All`

## Known limitations

- **Mailbox-level forwarding is not covered.** Graph does not expose it. Reported
  as a gap on every run; verify in Exchange Online PowerShell.
- **No message trace or quarantine.** Those live in Exchange Online and the
  security and compliance endpoints, not Graph. A second transport is needed.
- **Hybrid accounts.** Disabling in Entra is reverted at the next Entra Connect
  sync unless the on-premises account is disabled too. The action result says so
  when the account is synced.
- **Session revocation is not instantaneous.** Re-check sign-in logs after
  containment rather than assuming.
- **`-Scope Full` resets the password.** On an account holding a directory role
  this may require higher privilege than the app registration has.

## Tests

```bash
python3 Tests/Start-FakeM365.py &     # 127.0.0.1:8099
pwsh -File Tests/Invoke-IntegrationTest.ps1
```

The test double stages a full business email compromise — external forwarding
rule named `.` filing into RSS Feeds, Authenticator registered two days ago,
unverified app holding Mail.ReadWrite and Mail.Send, successful IMAP4 sign-in
from a second country, Helpdesk Administrator role, owned application, high
Identity Protection risk.

Verified on PowerShell 7.4:

- investigation issues **zero writes**; the dry run against a read-only context
  also issues zero writes, with all seven steps simulated
- 15 findings from the scenario: 3 Critical, 7 High, 2 Medium
- internal forwarding to `helpdesk@contoso.com` is correctly **not** flagged
- `moveToFolder` id resolves to `RSS Feeds`
- armed run hits the wire in the documented order, ending with the OAuth grant
  revocation and the Identity Protection call
- the generated password does not appear in `run.jsonl`; `[redacted]` does
- timestamps render as invariant UTC, not the runner's locale

## License

MIT.
