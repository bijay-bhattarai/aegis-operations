# Aegis Operations — Master Charter

The single document that defines what this project is, what it must never do,
and how work on it is run. Any agent or person picking this up reads this first.
Where this conflicts with a task instruction, this wins.

---

## 1. What this is

A supervised security operations workspace. Domain agents identify problems and
propose responses. Humans decide. The application records decisions and never
performs them.

The product claim is not "autonomous security." It is: every finding traces to a
rule, a standard, and a hashed artifact, and every decision traces to a named
person and a timestamp.

**The real objective.** This is a portfolio artifact built to demonstrate
identity and access management competence for a cybersecurity analyst role. That
governs scope. A narrow system running on real data beats a broad one running on
invention. When a choice is between more surface and more evidence, choose
evidence.

---

## 2. Non-negotiable constraints

These are enforced in code and covered by tests. They are not preferences and
not subject to a task instruction that asks to relax them.

**No execution.** No code path writes to any external system. No `fetch(`, no
`XMLHttpRequest`, no `sendBeacon` anywhere in `src/`. A repo-wide test fails if
one appears. Approval records a decision. Execution is attested by a human after
they acted outside the application.

**Agents propose, humans decide.** Agents may identify findings, link evidence,
raise severity, and propose actions. Agents may never dispose a finding, assign a
person as owner, lower severity, approve, reject, or assess a control. Those
require a module-private human capability.

**An agent is never a person.** A shared identity check rejects any supplied
person ID that names a known agent, including case variants and unicode
homoglyph or zero-width bypasses. It governs assessors, approvers, executors,
and evidence collectors alike. Its limits are documented in the module rather
than implied to be complete.

**Severity is computed, never asserted.** Rules supply decision points. The model
computes the band from a versioned policy. No caller passes a severity string.
Severity-reducing modifiers additionally require human review and cited evidence,
and a compensating-control reduction requires a referenced control with a current
human-recorded `tested_pass`.

**No conclusions without an assessor.** A control with no evidence is
`not_assessed`, never an implied pass. Reaching `tested_pass` or `tested_fail`
requires a named assessor and a timestamp. The application reports coverage. It
never asserts that anything is compliant, effective, secure, or within policy.

**Append-only history.** Every model keeps an ordered, immutable event log.
Corrections append a superseding event. Nothing is edited or deleted. A wrong
assessment, a wrong subject, or a wrong disposition is fixed by supersession, and
the original remains byte-identical in the log.

**No wall-clock reads.** Every projection takes an explicit `as_of`. State is
replayable at any past moment and overdue counts are reproducible. A timestamp
supplied by a reviewer is labeled unverified and cannot predate what it follows.

**Evidence is immutable and shared.** One global evidence repository. Evidence is
referenced by ID, never embedded. There is no removal or supersede path for an
evidence record. Conflicting records under the same ID are rejected.

---

## 3. Operating model

**Roles are separated deliberately.** The party that designs a change is not the
party that implements it. Claude specifies and attacks. Codex implements. This is
the same principle the architecture enforces elsewhere: whoever produces the work
does not also certify it.

Collapsing these roles removes the only independent check in the process. It has
already caught: five gaps in the control model, three in the finding model, two
in the action model, three uncaught exceptions on deep-linked routes, a dead-code
guard, an overfitted score, and a missing subject field that two rounds of design
review passed over.

**The loop.**

1. Claude writes a specification. For any model change, the specification asks
   for a proposed shape before implementation.
2. Codex implements against it and runs the suite.
3. Claude verifies by reading the repository directly and driving the browser.
   Never by reading a summary. A passing suite written by the implementer
   confirms the implementer's intent, not the absence of defects.
4. Commit only after verification. Push.

**Serial, not batched.** One task at a time. The next specification is written
after the previous one is verified and committed. The few minutes saved by
overlapping are not worth losing a known-good rollback point.

**Adversarial probing is standard.** Every model change is attacked, not
reviewed. Probe for: indirect routes around a new restriction, boundary and
off-by-one conditions, unicode and encoding bypasses, dead guards that can never
fire, state reachable out of order, and projections that leak superseded data.

**Optimize, with one limit.** Remove every step that costs time without buying
confidence. Never remove a step that buys confidence in order to save time. When
throughput and verifiability conflict, verifiability wins and the trade is stated
out loud rather than made quietly.

---

## 4. Standards for any change

- Frameworks are cited by pinned version, with a verification date. ATT&CK,
  CIS Controls, PCI DSS, and NIST publications all move. An unpinned citation
  drifts silently into being wrong.
- Every finding carries at least one NIST SP 800-53 control and one CIS
  safeguard. A finding with no control mapping is an observation, not a finding.
- Real data over synthetic. Synthetic seeds hide defects that real records
  expose. The missing subject field was invisible until two real users produced
  identical finding titles.
- A score is only meaningful against data the rules were not tuned on. Report
  recall and precision, then report the perturbation result separately.
- Generated artifacts are generated, not edited. `src/entra-finding-seeds.mjs`
  comes from the pipeline. A test fails if the committed file drifts from what
  the pipeline produces.
- State limitations in the record, not only in documentation.
  `verification_status: unverified` on an artifact is better than a paragraph
  explaining that artifacts are not resolved.
- Readable beats literal. An accurate interface nobody can read is a failure.
  Correctness constrains what is said, not whether it is legible.

---

## 5. Current state

Nine modules in `src/`, no build step, no backend. 131 tests. Five routed views:
Overview, Approvals, Findings, Controls, Audit.

**Real.** Ten identity findings derived from an actual Microsoft Entra ID
entitlement export, snapshot `2026-08-23T20:40:22Z`, SHA-256 pinned and verified
on every pipeline run. Every subject is a genuine Entra object ID. The rule
engine scores 1.00 recall, 1.00 precision, and 1.00 severity accuracy against a
published answer key, passes both control cases, detects 5 of 5 defects it was
never written against, and clears a removed defect with no side effects. The
pipeline regenerates the seed module and the score on every run and refuses to
write artifacts if the engine regresses.

**Staged.** Control records, agent proposals, and the agent personas.

One agent of five is real end to end. The others are descriptions.

---

## 6. What this is not

Session-only. No persistence. Reviewer identity is self-reported and not
authenticated. No artifact resolver, so content hashes are recorded but never
checked against bytes. Browser-side boundaries are domain boundaries, not runtime
protection against someone controlling the browser. No deployment pipeline, and
no agent may deploy, publish, or host this.

None of that is hidden. It is written into the records, the README, and the
handoff, because a system that overstates itself is worth less than one that
states its limits.
