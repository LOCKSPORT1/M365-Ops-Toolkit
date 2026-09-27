# RB-001 — Business email compromise response

| | |
| --- | --- |
| **Runbook id** | RB-001 |
| **Severity** | P1 when mail is being diverted or funds are in motion; P2 otherwise |
| **Target time to containment** | 30 minutes from confirmation |
| **Applies to** | Microsoft 365 tenants with Exchange Online |
| **Tooling** | `MtContainment` |
| **Last reviewed** | 2026-09-27 |

---

## When to use this

Any of the following:

- a user reports mail they sent was never received, or replies they expected never arrived
- a third party reports receiving unusual mail from one of your users, especially about payment details
- Identity Protection or Defender raises a high-risk sign-in
- a user reports an MFA prompt they did not initiate
- an inbox rule appears that the user does not recognise

The last two are frequently dismissed as user error. They are the two earliest reliable signals you get.

## When NOT to use this

- **Confirmed insider activity.** Stop and involve HR and legal before you touch the account. Containment destroys evidence you may need.
- **A user who simply forgot their password.** Run RB-002's identity section instead.
- **Suspected compromise of an account holding Global Administrator.** Follow this runbook, but escalate to a tenant-wide incident in parallel — a single-account response is the wrong scope.

---

## Before you start

- [ ] Confirm you have a ticket number. Every step below references it.
- [ ] Confirm you have the permissions listed in the `MtContainment` README, or an admin who does.
- [ ] Establish an **out-of-band** channel with the user — phone, in person, or a different messaging platform. Do not coordinate the response over the mailbox you are investigating.
- [ ] Note the time you were first notified. This becomes the start of your lookback window.

---

## Step 1 — Investigate before you touch anything (5 min)

Collection is read-only. Do this first, always, even when the compromise looks obvious.

```powershell
$ctx = New-MtTenantContext -TenantId '<tenant>' -ClientId $appId -CertificateThumbprint $thumb |
    Connect-MtTenant

$run = Start-MtRun -Name 'BEC-Response' -Context @($ctx) -Ticket '<ticket>'

$investigation = Get-MtUserInvestigation -Context $ctx -User '<upn>' -Days 7
$findings = Get-MtInvestigationFinding -Investigation $investigation
$findings | Where-Object { $_.Severity -in 'Critical','High' } | Format-Table Severity, Category, Title
```

**Why investigation precedes containment:** inbox rules and OAuth grants are evidence. Once deleted they are gone, and you will be asked what the attacker had access to. The investigation artifact preserves the rule definitions, the consented scopes, and the sign-in history before any of it is removed.

Widen `-Days` if the first suspicious sign-in sits at the edge of the window. Sign-in log retention is 30 days with Entra ID P1 or P2.

## Step 2 — Close the Graph blind spot (2 min)

Graph does not expose mailbox-level SMTP forwarding. The investigation flags this every run; it is not optional.

```powershell
Connect-ExchangeOnline
Get-Mailbox -Identity '<upn>' |
    Select-Object ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
```

If forwarding is set to an external address, treat it as confirmed compromise regardless of what else you found.

## Step 3 — Decide scope (3 min)

| Observation | Scope |
| --- | --- |
| Directory role held by the account | **Tenant incident.** Escalate. Review tenant-wide audit for the window, not just this user. |
| Account owns an application or service principal | **Tenant incident.** Check the app for credentials added during the window. |
| OAuth grant to an unverified publisher | Check whether **other users** consented to the same application. |
| External forwarding recipient identified | Search whether that address appears in **other mailboxes**. |
| Finance or executive user, or invoice keywords in a rule condition | Notify the client's finance contact **now**, before containment completes. Money moves faster than IT does. |

## Step 4 — Contain (10 min)

Dry run first. It uses the same code path and issues no writes.

```powershell
Invoke-MtAccountContainment -Context $ctx -Investigation $investigation -Scope Full
```

Review the simulated action list, then arm and execute:

```powershell
Set-MtWriteMode -Context $ctx -AllowWrites
$result = Invoke-MtAccountContainment -Context $ctx -Investigation $investigation -Scope Full
```

### The order, and why it is not arbitrary

1. **Disable the account** — fastest block on new authentication.
2. **Remove attacker-registered MFA** — before the reset. Otherwise the attacker completes self-service password reset with their own method and walks straight back in.
3. **Reset the password** — the credential itself.
4. **Revoke sessions** — **last**. A token minted between a revocation and a later password change survives. Revoke-then-reset leaves a window open; reset-then-revoke does not.
5. **Remove inbox rules** — persistence and evidence destruction.
6. **Revoke OAuth grants** — the only persistence that survives steps 1 through 5.
7. **Confirm compromised in Identity Protection** — feeds the signal back into risk policies.

### Hybrid accounts

If `onPremisesSyncEnabled` is true, disabling in Entra is reverted at the next Entra Connect sync. Disable the on-premises AD account as well:

```powershell
Disable-ADAccount -Identity '<samAccountName>'
```

Then force a sync, or wait for the cycle and verify.

## Step 5 — Verify (5 min)

- [ ] Re-run `Get-MtUserInvestigation`. Rules gone, grants gone, hostile auth methods gone, account disabled.
- [ ] Session revocation is **not instantaneous**. Re-check sign-in logs 15 minutes later for successful authentication after the revocation timestamp. If you see one, revoke again and escalate.
- [ ] Re-check mailbox forwarding in Exchange Online.
- [ ] If a hybrid account, confirm the AD account is disabled and has synced.

## Step 6 — Assess exposure (varies)

Questions you will be asked, so answer them now:

- What did the attacker have access to? Scopes on the revoked grant plus mailbox contents plus anything the directory role allowed.
- How long? First suspicious sign-in to containment.
- What was sent? Search sent items and message trace for the window.
- What was hidden? Check the folder any hostile rule filed mail into.
- Was anything else touched? The investigation's `InitiatedByUser` audit entries.

```powershell
Get-MessageTrace -SenderAddress '<upn>' -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)
```

## Step 7 — Restore access

Only after verification passes and the user's endpoint has been checked.

- [ ] Re-enable the account.
- [ ] Have the user re-register MFA from a known-good device, with you on the phone.
- [ ] Deliver the temporary password **out of band**. It is on the action result and deliberately not in the run log.
- [ ] Walk the user through what happened and what to watch for.

## Step 8 — Document and close

```powershell
Export-MtInvestigationReport -Investigation $investigation -Containment $result `
    -Path $run.Path -Ticket '<ticket>'
Complete-MtRun -Run $run -Outcome 'Contained'
```

Attach `report.md` to the ticket. It already contains the timeline, findings, actions taken, and what could not be checked.

---

## Communication templates

**To the user (out of band, immediately):**

> We've identified suspicious activity on your account and have temporarily disabled it while we investigate. This is precautionary and not something you did wrong. Please don't use email for anything related to this — I'll call you on [number]. If you've discussed payment details or bank information with anyone by email in the last week, tell me now.

**To the client contact (within 30 minutes):**

> We detected and contained a compromise of [user]'s Microsoft 365 account at [time]. The account is disabled, sessions revoked, and the attacker's persistence removed. We're now assessing what was accessed. Because [reason: invoice-related rule / finance user / external forwarding], please treat any payment instruction received by email from this account in the last [N] days as unverified until confirmed by phone. Full report to follow.

**Do not** send either of these to the compromised mailbox.

---

## Common pitfalls

- **Resetting the password first.** Feels like the obvious move; leaves refresh tokens valid for up to 90 days.
- **Missing OAuth consent.** Survives password reset, MFA re-registration, and session revocation. It is the reason accounts get re-compromised a week later.
- **Deleting rules before capturing them.** You lose the evidence and the answer to "what were they hiding."
- **Forgetting the on-premises side.** The account re-enables itself at the next sync and nobody notices.
- **Treating one mailbox as the whole incident.** Check whether the same OAuth app, or the same forwarding address, appears elsewhere.
- **Trusting a clean investigation.** Read the "Not checked" section before calling it clean.

## Escalate when

- The account held a directory role or owned an application object
- Successful sign-in appears after session revocation
- Funds have moved or payment details were changed
- The same indicator appears in a second mailbox
- Any evidence of on-premises lateral movement
