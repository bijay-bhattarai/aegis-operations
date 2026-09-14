# Aegis Operations handoff

## Product context

Owner: Bijay. Original vision: one cybersecurity workspace with SOC, Vulnerability, Identity, Compliance, and Security Engineering specialists and shared professional procedures.
Later requirements explicitly supersede the early "autonomous" product concept. Product tagline: Supervised security operations.
Framework labels are context, not proof that executable senior-level playbooks exist.

## Current implementation

Authored source lives in src/ with no build step. Static HTML/CSS with inline module JavaScript and six local ES modules. A shared immutable EvidenceRepository is the source of evidence records; controls and findings reference evidence by global ID. The Finding model uses one append-only event log, explicit replay timestamps, computed severity, versioned SLA policies, and human-only disposition and supersession. The dashboard overview computes control coverage plus open and overdue finding counts from demo records at one explicit `as_of`; its finding table renders projections from the same repository and orders overdue records before severity. The approval queue derives pending records from AgentAction state, resolves linked Finding evidence, and records reviewer decisions without initiating execution. No backend, LLM calls, integrations, persistent database, authenticated reviewer roles, artifact resolver or execution engine. Five agent panels describe supervised roles. Six action records start pending_approval. Five demo controls include one human-recorded tested pass, one human-recorded tested fail, one evidence-only record, and two records without evidence.

The browser model implements immutable snapshots, explicit transition checks, restricted agent/reviewer interfaces and a private assessment capability. These are local domain boundaries, NOT protection against someone controlling the browser runtime.

Identity spoofing is not defensible until identity is authenticated server-side. Collector-ID normalization catches only accidental and casual agent impersonation cases.

Control cycles are pinned to September 2026 UTC. Time checks reject new evidence or assessments outside that cycle. Do not quietly relabel historical data as current. Add an explicit cycle workflow if requested.

Current checks: 107 Node tests. They cover action and control state transitions, approval queue filtering and ordering, decision-time guards, finding event replay, severity and SLA calculation, dashboard indicator and finding-table wiring, copy and prominence, strict UTC calendar validation, data validation, restricted interfaces, structured evidence references, assessment and finding supersession history, a repository-wide source guard against outbound browser transports, some source checks, and script syntax. They do not establish production security, regulatory compliance, artifact resolution, authenticated identity, or live framework accuracy.

Finding replay decisions: risk acceptance expires inclusively, so a finding is open at exactly `acceptance_expires_at`. Supersede chains are permitted; a replacement event may itself be superseded, while every prior event remains in the log. Current evidence and action references are derived from active events only; superseded references remain visible in event history. Severity-reducing modifiers require human review and cited evidence. A `compensating_control` reduction also requires a finding-referenced control whose human-recorded `tested_pass` assessment covers its evidence set at the event timestamp.

## Important remaining work

1. Review runtime/UI behavior in a browser. Browser and WebMCP runtime testing has not been completed.
2. Human authorization is not production-grade. Before real use, bind reviewer identity to authenticated server-side roles and implement transactional persistence and tamper-evident audit history.
3. Keep no-execution/no-external-writes permanent. Backend work must not sneak in containment or remediation connectors.
4. AgentAction exposes a pure entity transition API and the separate control repository has a module-private human capability; align production authorization boundaries deliberately.
5. Review future-time handling and stale-cycle behavior.
6. Revisit action badges/record views for attribution completeness, schema-preserving presentation, and consistent wording.
7. Coverage "not yet tested" includes evidence_collected and exception_approved, while enum not_assessed specifically denotes no assessment. Keep that distinction documented.
8. Review demo finding seed suitability and risk metadata; overview values are computed from those session records at the displayed `as_of`.
9. Professional SOPs, retrieval knowledge, orchestration, authenticated evidence ingestion and production model evaluation are still unbuilt.

## Local-only operation and provenance

This repository has no deployment manifest or pipeline. Agents may not deploy, publish, or host it.
The source originated in an earlier prototype export.
This handoff summarizes relevant project conversation; it is not an imported Codex conversation thread.

## Recommended first task

Read the files, run the tests, inspect the UI locally, and report implementation gaps against AGENTS.md. Confirm the next bounded change with Bijay. Do not claim the prototype is production-ready.
