# Aegis Operations — supervised action refactor

## Data model

```typescript
export type AgentActionStatus =
  | "proposed" | "pending_approval" | "approved"
  | "rejected" | "expired" | "executed";

export interface AgentAction {
  action_id: string;
  agent_id: "soc" | "vuln" | "identity" | "compliance" | "engineering";
  action_type: string;
  target: string;
  justification: string;
  rule_id: string;
  control_refs: readonly string[];
  severity: "low" | "medium" | "high" | "critical";
  proposed_at: string; // UTC ISO 8601
  status: AgentActionStatus;
  approver: string | null;
  decided_at: string | null; // UTC ISO 8601
  decision_rationale: string | null;
  executed_at: string | null; // external execution attestation only
  rollback_procedure: string;
}
```

Runtime enforcement lives in `src/action-model.mjs`, not in UI handlers. Proposals cannot initialize decision fields or a later status. Snapshots are immutable. Failed changes leave the prior record intact. Agent ports expose propose, submit, get and list only. The separate human review port records decisions, expiry, and external execution attestations; it never performs execution.

Allowed transitions: proposed → pending_approval or expired; pending_approval → approved, rejected or expired; approved → executed or expired. Rejected, expired and executed are terminal. Approval/rejection requires nonblank approver, valid decision timestamp and rationale. Decision cannot predate proposal; execution cannot predate approval. No network APIs or response connectors exist. CSP denies connections and form submission.

This remains a session-only browser prototype, not an authenticated production approval service. Reviewer identity is self-reported and unverified. Refresh resets records. A future production service must enforce the same model server-side and bind reviewer identity to authenticated authorization. No claim of human authentication or durable audit storage is made.

## Changed and removed copy strings

All repeated occurrences are covered. Framework names and case evidence text not listed remain unchanged.

| Before | After |
|---|---|
| Autonomous defense | Supervised security operations. |
| Aegis Operations — an autonomous cybersecurity workforce governed by expert procedures, frameworks, and human-controlled policy. | Aegis Operations — supervised security operations. Agents propose; humans decide. Execution is recorded, never performed. |
| All systems nominal | Proposal-only model |
| 5 agents operating under Policy Set 4.2 | 5 agents · no execution capability |
| Acme Cloud · Production | Acme Cloud · Session-only demo |
| Operational posture · live | Operational posture · demo |
| Your security program is operating within policy. | Every agent action requires human review. |
| Five specialized agents are investigating, prioritizing, validating, and improving your defenses under approved expert procedures. | Five specialized agents analyzed evidence and proposed recommendations. No external-system writes are possible. |
| Alerts investigated | Alerts analyzed |
| Live agent activity | Agent proposals |
| Last 15 min | Demo records |
| Investigating 7 security alerts | Analyzed 7 security alerts |
| Prioritizing 42 findings | Prioritized 42 findings |
| Reviewing risky authentication | Flagged risky authentication |
| Testing 14 controls | Tested 14 controls |
| Detection change proposed | Proposed a detection change |
| Working | Proposal only |
| 5 of 5 active | 5 of 5 proposal-only |
| Every decision must cite evidence, an approved procedure, applicable framework guidance, and policy authorization. | Agents have no execution capability. Human decisions and external execution attestations are records only. |
| Correlates alerts across identity, endpoint, cloud, and network sources; distinguishes fact from hypothesis; assigns severity; preserves evidence; and routes containment through policy. | Correlated identity, endpoint, cloud, and network evidence; flagged compromise indicators; proposed containment for human review. |
| Validates whether an asset is affected, weighs internet exposure, exploit activity, asset criticality, compensating controls, and remediation risk—then verifies the fix. | Analyzed exposure, exploit activity, asset criticality, compensating controls, and remediation risk; prioritized findings; recommended a patch review. |
| Finds risky sign-ins, privilege creep, stale identities, and toxic access combinations while enforcing least privilege, separation of duties, and approval boundaries. | Flagged risky sign-ins, privilege creep, stale identities, and access conflicts; recommended an access review. |
| Tests whether controls actually operate, collects time-bound evidence, identifies gaps, prevents double counting, and keeps audit mappings traceable to source requirements. | Tested control criteria; validated evidence for control mappings; flagged gaps; proposed an evidence review. |
| Designs and tests detection and configuration changes, evaluates business impact, stages deployment, verifies results, and preserves a tested rollback path. | Analyzed detection coverage and change impact; tested rule criteria; proposed a detection change and rollback procedure. |
| Contain the affected identity | Proposed identity containment |
| Revoke active sessions, disable sign-in temporarily, and open an incident ticket. The account is privileged, so automatic execution is not permitted. | Proposed session revocation, temporary sign-in restriction, and incident documentation. Human review required; no response will be performed by this app. |
| Authorize emergency patch window | Proposed emergency patch review |
| Create a tested snapshot, apply the vendor remediation, validate service health, rescan, and retain rollback for 24 hours. | Recommended a human-managed patch window with snapshot, service checks, rescan evidence, and a 24-hour rollback plan. This app performs none of these steps. |
| Request access revocation | Proposed access review |
| Notify the application owner, preserve current entitlement evidence, and remove the production role after approval. | Recommended owner review of production access and entitlement evidence. Approval records a decision only; access remains unchanged. |
| SOC Agent correlated 4 signals | SOC Agent correlated 4 signals (unchanged heading; linked action and status badge added) |
| Likely identity compromise. Containment approval requested. | Proposed identity containment for human review. |
| Identity Agent revoked a session | Identity Agent proposed session revocation |
| Action permitted by IAM-IR-004 for a standard user. | Human approval required by IAM-IR-004; no session change. |
| Vulnerability Agent reprioritized CVE | Vulnerability Agent prioritized CVE |
| External exposure and KEV status raised risk to critical. | Recommended patch review based on exposure and KEV evidence. |
| Compliance Agent validated evidence | Compliance Agent validated evidence for SOC 2 CC6.1 |
| SOC 2 CC6.1 control remains effective. | Proposed human review of the control evidence. |
| Engineering Agent proposed a rule | Engineering Agent proposed a rule (unchanged heading; linked action and status badge added) |
| New Sentinel detection mapped to ATT&CK T1078. | Proposed Sentinel detection mapped to ATT&CK T1078. |
| 8 seconds ago; 2 minutes ago; 6 minutes ago; 11 minutes ago; 14 minutes ago | Removed fabricated relative timestamps; proposed_at is in each record. |
| Observe / Recommend / Execute; Default autonomy level | Proposal only · execution unavailable |
| Escalate to human / Approve containment | View action record |
| Approval / Assigned / Review (case row statuses) | pending_approval initially; dynamically reflects associated action status |
| Containment approved — policy workflow started. | Decision recorded for this session. No external action performed. |
| Case escalated with complete evidence package. | Removed; explicit record approval/rejection replaces message-only escalation. |
| Default autonomy set to ${b.dataset.mode}. | Removed with autonomy mutation handler. |
| Inspect security case | Inspect agent action |
| Open a known security case and return its verdict, evidence count, governing procedure, and policy gate. | Read a proposal record. No decision or external action is available. |
| Set default autonomy | Removed agent tool. |
| Change the visible default autonomy level for agent actions to Observe, Recommend, or Execute. | Removed agent tool. |
| Decide security case | Removed agent tool. |
| Approve the recommended response or escalate a known case to a human reviewer, using the same workflow as the visible case controls. | Removed agent tool. |

## Added review-interface copy

- Action record
- Close action record
- Session-only demo. Identities are self-reported, not authenticated. Refresh resets records. Approval never initiates execution.
- Approver identity (unverified demo input)
- Decision rationale
- Record approval
- Record rejection
- Expire record
- External execution attestation
- Record only work a human performed outside this application, after approval.
- Execution timestamp (UTC ISO 8601)
- YYYY-MM-DDTHH:mm:ss.sssZ
- I attest that execution occurred outside this app.
- Record external execution
- Confirm external execution before recording it.
- External execution attestation recorded. This app performed no action.
- Action expired. No external action performed.

## New action records and exact source changes

The accompanying `refactor.diff` includes every changed, deleted, and added string verbatim, including all six action records, rollback text, runtime validation errors, status enum values, accessibility labels, and agent-tool schemas. It also includes the complete new model and tests. CSS tokens such as `position:fixed` and the native `disabled` property are not agent activity verbs.

## Verification

45 Node checks pass: every state-pair transition, five restricted agent ports, required approval metadata, time ordering, immutable snapshots, initialization bypass rejection, UI syntax, removed decision/autonomy tools, and absence of outbound writer APIs. Browser UI and WebMCP runtime QA were not performed.

## Structured evidence-reference copy

- Evidence source system
- Entra ID
- Artifact type
- Export
- Screenshot
- Log query
- Attestation
- Configuration snapshot
- Artifact locator
- artifact://session/...
- Artifact SHA-256
- 64 lowercase hexadecimal characters
- Collector type
- Agent
- Person (self-reported)
- Collector ID
- compliance
- Evidence reference collected. Artifact remains unverified because this demo has no artifact resolver.

## Finding SLA copy

| Removed fabricated demo label | Replacement |
|---|---|
| VUL-SLA-001 · 24-hour remediation | VUL-SLA-001 · Rule-specific SLA |

## Computed overview indicators

- Control coverage
- Open findings by severity
- Overdue findings by severity
- As of 2026-09-14T23:00:00Z
- Critical-priority demo observation
- High-priority demo observation
- Expired acceptance demo observation
- Low-priority demo observation
- Human-closed demo observation

## Overview readability pass

| Previous | Current |
|---|---|
| Assessment observations | Operations overview |
| Coverage counts pending record initialization. | Welcome back, Bijay. |
| Demo observations. No authenticated assessment records. Refresh resets this session. | Review control coverage, open findings, and overdue work at the shared snapshot below. |
| Assessment cycle · September 2026 UTC | Today’s review |
| Cycle · September 2026 UTC | Session-only demo |
| Control records · September 2026 UTC | Control records |
| Not assessed first | Needs assessment first |
| Observations · September 2026 UTC | Awaiting human decisions |
| Agent scope · September 2026 UTC | Five supervised roles |
| Pending review | Ready for review |
| Raw action states such as `pending_approval` | Reader-facing labels such as `Awaiting approval` |
| Approval | Awaiting approval |
| Observed rule proposal · September 2026 UTC | Drafts detection changes with rollback guidance |

Agent tiles now describe each role’s work: correlating operational evidence, prioritizing exposure evidence with SSVC, reviewing identity evidence, mapping evidence to controls, and drafting detection changes. Repeated cycle labels were removed from the overview, agent tiles, proposal feed, and control rows; evidence records retain dates where they establish provenance.

## Finding table and shared snapshot

| Previous | Current |
|---|---|
| Three repeated `As of` labels in the indicator cards | One `Snapshot as of` timestamp above the indicators |
| Case observations | Finding records |
| Case / Observation / Assessment / Window / Status | Finding / Title / Severity / State / Owner / SLA status |
| Hardcoded INC-2841, VUL-9912, and IAM-2204 rows | Finding projections from the shared demo repository |
| Within sla | Within SLA |

Finding rows are ordered with overdue records first, then by computed severity. Each row presents the owner and SLA state from the projection at the shared snapshot.

## Microsoft Entra finding provenance

- The five `F-DEMO-*` finding labels were removed.
- The finding table now renders ten `IAM-0001` through `IAM-0010` records derived from the supplied Microsoft Entra ID entitlement export.
- The finding-section header shows the evidence collection timestamp and a truncated SHA-256 from the shared evidence record.
- The identity action copy now names the R04 disabled-account entitlement observation and the R01 cross-department privileged-role observation that each proposal references.
- Finding rows now identify the subject by display label.
- The finding drawer shows subject type, stable identifier, identity attributes, and rule-specific observed facts as separate keys and values.

## Four routed views

| Removed navigation | Current destination |
|---|---|
| AI workforce | Agent workforce panel on Overview |
| Incidents | Finding type filter on Findings |
| Exposure | Finding type filter on Findings |
| Identity | Finding type filter on Findings |
| Governance | Controls |

- Overview
- Approvals
- Findings
- Controls
- Highest-priority open findings
- First four at the shared snapshot
- Finding filters
- All severities
- All states
- All SLA states
- All finding types
- Assessment state and attribution

Each view has a linkable hash and displays the same shared snapshot. Action, finding, and control drawers use nested hashes under their parent view.

Unknown or incomplete drawer links return to their parent view and announce “Finding record was not found.”, “Action record was not found.”, or “Control record was not found.” in the non-blocking status notice.

## Approval queue

- Approvals
- Actions awaiting approval
- Full justification
- Evidence linked through finding records
- Rollback procedure
- Approver identity (unverified demo input)
- Decision timestamp (UTC ISO 8601; reviewer-supplied, unverified)
- Decision rationale
- Record approval
- Record rejection
- External execution attestation

Proposed actions explain that the proposing agent must submit them before a reviewer can decide. Approval copy states that the decision performs no action; external execution remains a separate human attestation.

Action expiry now asks for the actor type, actor identity, timestamp, and reason. External execution attestation now asks for the executor identity. These self-reported inputs provide event attribution in the session-only action history; they do not authenticate either person or system identities.

## Audit view

- Audit
- Audit event stream
- Snapshot as of
- Session-only log; this browser record is not tamper-evident.
- Actor type / All actor types
- Record type / All record types
- Timestamp / Actor / Event type / Record / Change
- Superseded / View replacement
- Supersedes prior event / View original
- Open related record
- Full event payload

Person-attributed events use the strongest visual treatment in the stream. Audit rows are display projections of existing finding, control, and action history; the interface does not store a separate audit record.
