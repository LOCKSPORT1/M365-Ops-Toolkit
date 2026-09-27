# RB-003 — New client tenant onboarding

| | |
| --- | --- |
| **Runbook id** | RB-003 |
| **Severity** | P3 planned |
| **Target time** | Discovery in one day; full onboarding across 2–4 weeks |
| **Applies to** | Taking over management of an existing Microsoft 365 tenant |
| **Tooling** | `MtGraph`, `MtAzurePosture`, `MtContainment` |
| **Last reviewed** | 2026-09-27 |

---

## When to use this

Assuming management of a tenant you did not build. The tenant has history: prior administrators, abandoned projects, undocumented integrations, and at least one thing nobody can explain.

## The principle

**Document before you change anything.**

The first week is the only time you will ever see the environment as it was handed to you. After that, every problem is arguably yours. A complete "as found" record protects the client, protects you, and is the baseline every later improvement is measured against.

---

## Phase 1 — Access and authorisation (day 1)

- [ ] Signed agreement covering the scope of administrative access
- [ ] Named authorised contacts, with a documented process for verifying requests
- [ ] Access established — GDAP relationship, or delegated admin accounts, per your standard
- [ ] App registration consented with the read scopes your tooling needs
- [ ] **Break-glass accounts identified or created**, excluded from Conditional Access, credentials stored offline
- [ ] Escalation path and out-of-hours expectations agreed in writing

### Before you accept the tenant

Ask, and record the answers:

- Who else currently holds administrative access, including the prior provider?
- Are there service accounts, and does anyone know their passwords?
- Is there an existing MFA or Conditional Access deployment, and are there exclusions?
- Any regulatory obligations — CMMC, HIPAA, PCI, CJIS, contractual data-handling terms?
- Any Azure subscriptions, and under whose billing?
- Which third-party applications hold tenant-wide consent?

"We don't know" is a valid answer and a finding in its own right. Write it down.

## Phase 2 — Discovery (day 1–3)

Read-only. Nothing in this phase changes anything.

```powershell
$ctx = New-MtTenantContext -TenantId '<tenant>' -ClientId $appId -CertificateThumbprint $thumb |
    Connect-MtTenant

$run = Start-MtRun -Name 'TenantOnboarding-Discovery' -Context @($ctx) -Ticket '<ticket>'

# Licensing drives what is even possible here.
Get-MtTenantCapability -Context $ctx
```

Capability discovery first. Half the recommendations you would otherwise make depend on licences the tenant may not hold, and proposing Identity Protection to an E3 tenant undermines everything else you say.

### Identity and access

```powershell
# Conditional Access as found
Invoke-MtGraphRequest -Context $ctx -Uri 'identity/conditionalAccess/policies' -All |
    Select-Object displayName, state

# Who holds privilege
Invoke-MtGraphRequest -Context $ctx -Uri 'directoryRoles' -All

# Tenant-wide application consent
Invoke-MtGraphRequest -Context $ctx -Uri 'oauth2PermissionGrants' -All
```

Check specifically:

- Conditional Access policies in **report-only** — someone built them and never enforced them
- **Exclusions** on every policy. Exclusions are where the real posture lives.
- Accounts holding Global Administrator. More than four is a finding; standing assignment rather than PIM is a finding.
- Legacy authentication: blocked, or merely unused?
- Security defaults on or off
- Applications holding tenant-wide consent with mail or file scopes

### Azure

```powershell
$posture = Get-MtAzurePosture -Context $ctx
Get-MtAzureFinding -Posture $posture | Where-Object { $_.Severity -in 'Critical','High' }
```

### Endpoints, mail, and everything else

- Intune enrolment, compliance policies, configuration profiles, and **policy conflicts**
- Autopilot registrations and deployment profiles
- Exchange transport rules — especially anything forwarding externally
- Mailbox-level forwarding across all mailboxes (Graph does not expose this)
- Shared and orphaned mailboxes
- Any on-premises footprint: AD, Entra Connect, file servers, line-of-business applications
- Backup: what is protected, and has a restore ever been tested?

## Phase 3 — The "as found" report (day 3–5)

Deliver a written baseline. It should contain:

1. **Inventory** — users, licences, domains, devices, Azure resources
2. **Identity posture** — CA policies and their exclusions, privileged accounts, MFA coverage, legacy auth state
3. **Findings**, prioritised, with what each one actually risks
4. **What you could not determine**, and why
5. **Recommended remediation**, sequenced, with effort and dependencies
6. **Risks you are accepting on day one** if remediation is deferred

That last section matters more than it looks. It converts "we inherited a mess" from a complaint into a documented, dated, client-acknowledged position.

Findings a takeover almost always surfaces:

- Global Administrator accounts without MFA
- Conditional Access in report-only for months
- Legacy authentication permitted
- Former employees' accounts still enabled
- Shared admin credentials
- Mailbox forwarding nobody knew about
- Internet-facing RDP in Azure
- Backups configured but never restore-tested

## Phase 4 — Stabilise (week 1–2)

Fix what is actively dangerous. Do not redesign anything yet.

Order by risk, not by ease:

1. MFA on every privileged account
2. Disable accounts for people who have left
3. Remove external mailbox forwarding that has no business justification
4. Close internet-facing management ports
5. Revoke tenant-wide consent for applications nobody can account for
6. Rotate shared credentials
7. Get break-glass accounts verified and tested

**Change control from day one.** Every change gets a ticket, a documented before-state, a rollback plan, and client approval. The temptation to "just fix it quickly" during onboarding is how you end up owning an outage you cannot explain.

## Phase 5 — Standardise (week 2–4)

Bring the tenant toward your baseline.

- [ ] Conditional Access aligned to your standard set, deployed report-only first, then enforced with a documented rollback
- [ ] Naming conventions and group structure
- [ ] Intune compliance and configuration baselines
- [ ] Monitoring and alerting wired to your channels, with a verified test alert
- [ ] Backup verified by an actual restore, not a green dashboard
- [ ] Onboarding and offboarding procedures agreed with the client (see RB-002)
- [ ] Documentation published where the client can see it

**Report-only first, always.** A Conditional Access policy that locks out a department on a Friday afternoon undoes months of goodwill.

## Phase 6 — Operational handover (week 4)

- [ ] Tenant added to the monitored book and the drift baseline
- [ ] Runbooks updated with anything specific to this client
- [ ] Support process communicated to the client's users
- [ ] Escalation contacts confirmed on both sides
- [ ] Review cadence scheduled
- [ ] Prior provider's access **removed and verified** — not assumed

That last item is skipped constantly. Verify it yourself:

```powershell
Invoke-MtGraphRequest -Context $ctx -Uri 'directoryRoles' -All
Invoke-MtGraphRequest -Context $ctx -Uri 'servicePrincipals?$filter=appOwnerOrganizationId ne null' -All
```

---

## Common pitfalls

- **Changing things during discovery.** You lose the baseline, and now every problem is yours.
- **Assuming the prior provider's access is gone.** Check delegated admin relationships, app registrations, and role assignments yourself.
- **Enforcing Conditional Access without report-only.** The fastest way to a P1 in week two.
- **Trusting the backup dashboard.** Test a restore.
- **Not documenting accepted risk.** Without it, deferred remediation becomes your fault later.
- **Proposing features the licensing does not include.** Run capability discovery first.
- **Skipping break-glass.** Then a Conditional Access change locks everyone out, including you.
- **Onboarding without a signed scope.** You will end up owning something you never agreed to.

## Verification checklist

- [ ] "As found" report delivered and acknowledged in writing
- [ ] Break-glass accounts created, excluded from CA, tested, stored offline
- [ ] Every privileged account has MFA
- [ ] Prior provider access removed and verified
- [ ] Tenant in the monitored book and the drift baseline
- [ ] Backup restore tested
- [ ] Monitoring alert tested end to end
- [ ] Change control operating
- [ ] Accepted risks documented and dated
