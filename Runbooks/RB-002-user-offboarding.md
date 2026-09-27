# RB-002 — User offboarding (leaver)

| | |
| --- | --- |
| **Runbook id** | RB-002 |
| **Severity** | P2 routine; **P1 for an involuntary termination** |
| **Target time** | 20 minutes for the identity steps; data handover follows |
| **Applies to** | Microsoft 365 tenants, hybrid or cloud-only |
| **Tooling** | `MtContainment` (identity actions), `MtGraph` |
| **Last reviewed** | 2026-09-27 |

---

## When to use this

A user is leaving the organisation: resignation, termination, contract end, or a long leave where access should lapse.

## The one distinction that changes everything

**Involuntary termination is a security event, not an admin task.** Access must be cut at or before the moment the person is told, not when the ticket reaches the queue. Agree the exact cutoff time with HR in advance and execute to it.

Everything else in this runbook is the same; only the timing and the order change.

---

## Before you start

- [ ] Written authorisation from HR or the client's authorised contact. Never offboard on a verbal request or a forwarded email.
- [ ] Confirm the **exact** UPN. Similar names are how the wrong person gets disabled.
- [ ] Confirm the termination type and the cutoff time.
- [ ] Identify who receives the mailbox, the OneDrive contents, and any delegated access.
- [ ] Confirm the licence decision: reclaim immediately, or hold for a retention period.
- [ ] Ask explicitly: **does this person hold any shared or service credentials?** This is the question that gets missed.

---

## Step 1 — Capture what they have, before you change it (5 min)

Read-only. Do this first even under time pressure — after you disable the account, some of this becomes harder to enumerate.

```powershell
$ctx = New-MtTenantContext -TenantId '<tenant>' -ClientId $appId -CertificateThumbprint $thumb |
    Connect-MtTenant

$run = Start-MtRun -Name 'UserOffboarding' -Context @($ctx) -Ticket '<ticket>'
$leaver = Get-MtUserInvestigation -Context $ctx -User '<upn>' -Days 30
```

The investigation gives you, in one pass:

- group and directory role membership — what access is about to disappear
- **owned objects** — applications, service principals and groups that will become ownerless
- registered and managed devices — what needs collecting or wiping
- OAuth grants — third-party applications holding delegated access
- registered auth methods — what to remove

Record it. `Export-MtInvestigationReport` produces the handover evidence without you writing it out.

### Ownerless objects are the trap

If the leaver owns an application registration, a service principal, or a group, reassign ownership **now**. An ownerless app whose certificate expires in eight months becomes an outage nobody can diagnose, because the only person who could renew it left.

## Step 2 — Identity cutoff (5 min)

For a **voluntary** departure, at the agreed date and time. For an **involuntary** one, at the moment HR specifies — often before the conversation happens.

```powershell
Set-MtWriteMode -Context $ctx -AllowWrites

Disable-MtUserAccount -Context $ctx -UserId $leaver.UserId -Account $leaver.Account
Revoke-MtUserSession -Context $ctx -UserId $leaver.UserId
```

Sessions must be revoked, not just the account disabled. Disabling blocks new authentication; existing refresh tokens keep working until revoked.

**Hybrid:** disable the on-premises AD account too, or the next Entra Connect sync re-enables it.

```powershell
Disable-ADAccount -Identity '<samAccountName>'
Move-ADObject -Identity '<distinguishedName>' -TargetPath '<disabled users OU>'
```

**Do not delete the account.** Deletion destroys the mailbox, the OneDrive, the audit trail, and the ability to answer questions later. Disable now; delete at the end of the retention period, if at all.

## Step 3 — Revoke third-party access (2 min)

```powershell
foreach ($grant in @($leaver.OAuthGrants)) {
    Revoke-MtUserOAuthGrant -Context $ctx -GrantId $grant.Id -ApplicationName $grant.Application
}
```

Disabling the account does not immediately invalidate every third-party token minted against it. Revoke the grants explicitly.

## Step 4 — Mail (5 min)

```powershell
Connect-ExchangeOnline

# Convert to shared: retains contents, and a shared mailbox under 50 GB needs no licence.
Set-Mailbox -Identity '<upn>' -Type Shared

# Delegate to the manager or successor.
Add-MailboxPermission -Identity '<upn>' -User '<manager>' -AccessRights FullAccess -InheritanceType All

# Optional: allow the delegate to send as the departed user.
Add-RecipientPermission -Identity '<upn>' -Trustee '<manager>' -AccessRights SendAs
```

Decide deliberately about an auto-reply. A reply naming the successor is helpful internally and is also free reconnaissance for anyone probing the organisation. For a departure under difficult circumstances, use a neutral message with no name.

**Check for existing forwarding and rules** before handing the mailbox over. A leaver who set forwarding to a personal address is a data exfiltration event, not a housekeeping item.

## Step 5 — Files and collaboration (varies)

- **OneDrive:** set the manager as secondary owner before the retention period elapses. Default retention after account deletion is 30 days unless configured otherwise — verify the tenant's setting rather than assuming.
- **SharePoint and Teams:** transfer ownership of any site or team where the leaver was the sole owner. Same failure mode as ownerless apps.
- **Shared mailboxes and calendars:** remove their delegated access.

## Step 6 — Devices (varies)

From the investigation's device list:

| Situation | Action |
| --- | --- |
| Corporate device, being returned | Retire from Intune after collection; re-image before reissue |
| Corporate device, not recoverable | **Wipe**, not retire |
| Personal device (BYOD) | Retire — removes company data, leaves personal data |
| Involuntary termination, device not yet collected | Wipe immediately; do not wait |

Retire removes company data. Wipe factory-resets. Choosing wrongly either leaves data on a device you do not control, or destroys someone's personal photos and generates a complaint.

## Step 7 — Licensing and cleanup (5 min)

- [ ] Remove group memberships that drive licence assignment
- [ ] Reclaim the licence, or note the hold date
- [ ] Remove from distribution lists and security groups
- [ ] Remove from any third-party SaaS with SSO or SCIM — SCIM-provisioned apps deprovision on group removal, but verify rather than assume
- [ ] Remove from on-call rotations, alerting action groups, and shared accounts
- [ ] Update any documentation naming them as an owner or contact

## Step 8 — Credentials they held

If the leaver had access to shared or service credentials — a service account password, an API key, a shared admin account, a vendor portal login — **rotate them**. All of them.

This is the step that gets skipped because it is inconvenient and nobody is measuring it. It is also the step that matters most three months later.

## Step 9 — Document and close

```powershell
Export-MtInvestigationReport -Investigation $leaver -Path $run.Path -Ticket '<ticket>'
Complete-MtRun -Run $run -Outcome 'Offboarded'
```

Record: who authorised it, what was disabled and when, where the mail and files went, which devices were retired or wiped, which credentials were rotated, and the scheduled deletion date.

---

## Involuntary termination — condensed sequence

Run in this order, at the time HR specifies, ideally while the conversation is happening:

1. Disable account + revoke sessions (Step 2), on-premises and cloud simultaneously
2. Wipe or retire devices (Step 6)
3. Revoke OAuth grants (Step 3)
4. Rotate shared credentials (Step 8)
5. Convert mailbox and delegate (Step 4) — after the immediate cutoff
6. Everything else at normal pace

Capture the investigation (Step 1) **beforehand** if you have advance notice. If you do not, capture it immediately after the cutoff rather than skipping it.

---

## Common pitfalls

- **Deleting instead of disabling.** Irreversible, and destroys the audit trail you will be asked for.
- **Disabling without revoking sessions.** Existing tokens keep working.
- **Forgetting the on-premises account.** It re-enables at the next sync.
- **Missing ownerless objects.** Surfaces as an outage months later with no one able to fix it.
- **Not rotating shared credentials.** The most common real gap in offboarding.
- **Auto-reply naming the successor.** Convenient internally, useful to an attacker externally.
- **Retiring a device that should have been wiped**, or the reverse.
- **Offboarding the wrong user.** Confirm the UPN, not the display name.

## Verification checklist

- [ ] Sign-in blocked, cloud and on-premises
- [ ] No successful sign-in after the cutoff timestamp
- [ ] Mailbox converted, delegated, forwarding checked
- [ ] OneDrive and SharePoint ownership transferred
- [ ] Devices retired or wiped as appropriate
- [ ] OAuth grants revoked
- [ ] Licences reclaimed or held per the decision
- [ ] Owned objects reassigned
- [ ] Shared credentials rotated
- [ ] Deletion date recorded
