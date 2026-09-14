# Aegis Operations handoff

## Product context

Owner: Bijay. Original vision: one cybersecurity workspace with SOC, Vulnerability, Identity, Compliance, and Security Engineering specialists and shared professional procedures.
Later requirements explicitly supersede the early "autonomous" product concept. Product tagline: Supervised security operations.
Framework labels are context, not proof that executable senior-level playbooks exist.

## Current implementation

Authored source lives in src/ with no build step. Static HTML/CSS with inline module JavaScript and local ES modules. A shared immutable EvidenceRepository is the source of evidence records; controls and findings reference evidence by global ID. Finding and AgentAction each use one authoritative append-only event log with explicit `as_of` projection and human-only supersession. AgentAction derives every current field from active events; proposal, submission, decision, expiry, and external execution attestation events all carry an actor and timestamp. Its projection exposes the executor or the expiry timestamp and actor when applicable. Action approver and executor person IDs reuse the evidence collector's normalized agent-impersonation check. The Finding model also provides computed severity, versioned SLA policies, and human-only disposition. Identified events require an immutable typed subject and structured rule-fact lines; only identity-user and vulnerability-asset subject mappings currently exist. The interface has five hash-routed views: Overview, Approvals, Findings, Controls, and Audit. Overview contains computed indicators, the shared snapshot, the supervised agent panel, and four highest-priority open findings. Approvals contains the full-width action queue. Findings contains the complete filtered table. Controls presents assessment state, assessor, assessment timestamp, and cycle. Audit derives one newest-first stream from finding events, control evidence and assessments, and AgentAction history; it stores no parallel log. Actor and record filters, immutable payload drawers, supersession links, and related-record drawer routes all use the shared `as_of`. Nested action, finding, control, and audit-event hashes restore drawers on reload. The ten identity findings derive from the supplied Microsoft Entra ID entitlement export and reference one evidence record containing the export's SHA-256 and collection timestamp. The approval queue derives pending records from AgentAction state, resolves linked Finding evidence, and records reviewer decisions without initiating execution. No backend, LLM calls, integrations, persistent database, authenticated reviewer roles, artifact resolver or execution engine. Five agent panels describe supervised roles. Three action records start pending_approval; two identity proposals link to real Entra findings and one separate compliance proposal links to a control. Five demo controls include one human-recorded tested pass, one human-recorded tested fail, one evidence-only record, and two records without evidence.

The browser model implements immutable snapshots, explicit transition checks, restricted agent/reviewer interfaces and a private assessment capability. These are local domain boundaries, NOT protection against someone controlling the browser runtime.

Identity spoofing is not defensible until identity is authenticated server-side. Collector-ID normalization catches only accidental and casual agent impersonation cases.

Control cycles are pinned to September 2026 UTC. Time checks reject new evidence or assessments outside that cycle. Do not quietly relabel historical data as current. Add an explicit cycle workflow if requested.

Current checks: 129 Node tests. They cover the derived unified audit stream, newest-first ordering, immutable payloads, supersession links, audit filters and record routes, append-only action history and replay, attributed action transitions and terminal projections, normalized person-ID checks, action supersession, action and control state transitions, approval queue filtering and ordering, decision-time guards, finding event replay, severity and SLA calculation, the five hash routes, shared snapshot wiring, finding filters, compact overview findings, nested drawer routes including missing-record fallback, copy and prominence, strict UTC calendar validation, data validation, restricted interfaces, structured evidence references, assessment and finding supersession history, a repository-wide source guard against outbound browser transports, source checks, and script syntax. They do not establish production security, regulatory compliance, artifact resolution, authenticated identity, or live framework accuracy.

Finding replay decisions: risk acceptance expires inclusively, so a finding is open at exactly `acceptance_expires_at`. Supersede chains are permitted; a replacement event may itself be superseded, while every prior event remains in the log. Current evidence and action references are derived from active events only; superseded references remain visible in event history. Severity-reducing modifiers require human review and cited evidence. A `compensating_control` reduction also requires a finding-referenced control whose human-recorded `tested_pass` assessment covers its evidence set at the event timestamp.

## Important remaining work

1. Review runtime/UI behavior in a browser. Browser and WebMCP runtime testing has not been completed.
2. Human authorization is not production-grade. Before real use, bind reviewer identity to authenticated server-side roles and implement transactional persistence and tamper-evident audit history.
3. Keep no-execution/no-external-writes permanent. Backend work must not sneak in containment or remediation connectors.
4. AgentAction exposes a pure entity transition API and the separate control repository has a module-private human capability; align production authorization boundaries deliberately.
5. Review future-time handling and stale-cycle behavior.
6. Revisit action badges/record views for attribution completeness, schema-preserving presentation, and consistent wording.
7. Coverage "not yet tested" includes evidence_collected and exception_approved, while enum not_assessed specifically denotes no assessment. Keep that distinction documented.
8. Keep the Entra severity mapping aligned with ENTRA_FINDING_RULES.md. R05 describes operational harm from missing access; it is not an excessive-access rule.
9. Professional SOPs, retrieval knowledge, orchestration, authenticated evidence ingestion and production model evaluation are still unbuilt.

## Local-only operation and provenance

This repository has no deployment manifest or pipeline. Agents may not deploy, publish, or host it.
The source originated in an earlier prototype export.
This handoff summarizes relevant project conversation; it is not an imported Codex conversation thread.

## Recommended first task

Read the files, run the tests, inspect the UI locally, and report implementation gaps against AGENTS.md. Confirm the next bounded change with Bijay. Do not claim the prototype is production-ready.
