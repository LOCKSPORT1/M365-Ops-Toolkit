# Runbooks

Operational procedures for multi-tenant Microsoft 365 and Azure administration.
Each one is written to be executed under pressure by someone who did not write
it, and each is paired with the tooling that automates the mechanical parts.

| Id | Runbook | Severity | Tooling |
| --- | --- | --- | --- |
| [RB-001](RB-001-business-email-compromise.md) | Business email compromise response | P1 / P2 | `MtContainment` |
| [RB-002](RB-002-user-offboarding.md) | User offboarding (leaver) | P2 / P1 if involuntary | `MtContainment`, `MtGraph` |
| [RB-003](RB-003-tenant-onboarding.md) | New client tenant onboarding | P3 planned | `MtGraph`, `MtAzurePosture` |

## How these are written

**Read before you write.** Every runbook that touches a live environment starts
with a read-only collection step, because inbox rules, OAuth grants and group
memberships are evidence, and once removed they are gone.

**Order is documented, with the reason.** "Revoke sessions last" is not a style
preference — a token minted between a revocation and a later password change
survives. Where sequence matters, the runbook says why, so the step does not get
reordered by someone optimising for speed.

**Gaps are named.** Where a tool cannot see something — Graph does not expose
mailbox-level SMTP forwarding — the runbook names the gap and gives the command
that closes it. A procedure that silently omits a check produces a false
all-clear.

**Decision points are explicit.** Retire or wipe. Voluntary or involuntary.
Mailbox incident or tenant incident. These are the choices that go wrong under
time pressure, so they are tables rather than prose.

**Every runbook ends with a verification checklist**, because "I ran the steps"
and "the outcome is correct" are different claims.

## Conventions

- Commands assume the tooling in this repository is imported and a tenant
  context is connected.
- `<placeholders>` in angle brackets are substituted per incident.
- Write operations require an armed context (`Set-MtWriteMode -AllowWrites`).
  Everything else is read-only by default and safe to run on a hunch.
- Every procedure produces an artifact fit to attach to the ticket.

## Review

Runbooks are reviewed when the underlying platform changes, when an incident
exposes a gap, and at least twice a year. The review date is in each header —
an unreviewed runbook is a liability, not an asset.
