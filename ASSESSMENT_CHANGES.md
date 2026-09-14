# Assessment and status copy refactor

## New data model

```typescript
type ControlStatus =
  | "not_assessed"
  | "evidence_collected"
  | "tested_pass"
  | "tested_fail"
  | "exception_approved";

interface Control {
  control_id: string;
  name: string;
  cycle_id: string;
  cycle_start: string; // UTC, inclusive
  cycle_end: string;   // UTC, exclusive
  status: ControlStatus; // defaults to not_assessed
  evidence: ReadonlyArray<{
    evidence_id: string;
    source: string;
    collected_at: string; // UTC, within cycle
  }>;
  assessor: string | null;
  assessed_at: string | null; // UTC, within cycle
  assessment_rationale: string | null;
}
```

Runtime implementation: `src/control-model.mjs`. Constructor forbids status or assessor injection. The agent port exposes only get/list/collect; a module-private capability guards assessment transitions. No evidence means not_assessed. Only evidence_collected may become tested_pass, tested_fail or exception_approved, with nonblank assessor, UTC assessed_at and rationale. Assessment follows evidence within the cycle. New evidence clears prior assessment metadata and returns status to evidence_collected. Exceptions do not count as tests or passes. Missing attribution suppresses individual conclusions. Records and nested evidence snapshots are immutable.

Coverage is computed, not stored. In the headline, not_assessed means all controls not yet tested, including evidence_collected and exception_approved. The exact enum state remains visible in the control list. Ordering: not_assessed, evidence_collected, tested_fail, exception_approved, tested_pass.

## All changed or removed copy (relative to the unpublished action refactor)

Each replacement applies to all occurrences. The separate action-refactor ledger is COPY_CHANGES.md. Empty replacements indicate removal. Markup is stripped below for readability; assessment-source.diff contains exact source changes.

| Before | After |
|---|---|
| Operational posture · demo | Assessment cycle · September 2026 UTC |
| Every agent action requires human review. | Coverage counts pending record initialization. |
| Five specialized agents analyzed evidence and proposed recommendations. No external-system writes are possible. | Demo observations. No authenticated assessment records. Refresh resets this session. |
| Good evening, Bijay. | Assessment observations |
| 5 agents · no execution capability | Agent scope · September 2026 UTC |
| 5 of 5 proposal-only | Agent scope · September 2026 UTC |
| Analyzed 7 security alerts | Observed alert records · September 2026 UTC |
| Prioritized 42 findings | Observed exposure records · September 2026 UTC |
| Flagged risky authentication | Observed authentication records · September 2026 UTC |
| Tested 14 controls | Collected control evidence · September 2026 UTC |
| Proposed a detection change | Observed rule proposal · September 2026 UTC |
| Proposal only | Pending review |
| Demo records | Observations · September 2026 UTC |
| Governance core enforced | Action recording constraints |
| Cases requiring attention | Case observations · September 2026 UTC |
| Finding | Observation |
| Probable Microsoft 365 account compromise | Microsoft 365 sign-in and download records |
| Internet-exposed gateway affected by known exploit | Gateway inventory and exposure records |
| Dormant privileged account retained production access | Account activity and entitlement records |
| Probable account compromise | Sign-in and download observations |
| Compromise highly likely | Pending review |
| Four independent signals corroborate unauthorized account access. Facts and inference are separated below. | Sign-in, authentication-method, download, and threat-feed records collected during September 2026 UTC. |
| Exploitable internet gateway | Gateway observations |
| Remediation priority: immediate | Pending review |
| The finding is validated, externally reachable, and associated with known exploitation. Business impact has been checked. | Inventory, reachability, catalog, and dependency records collected during September 2026 UTC. |
| Access violates policy | Pending review |
| An inactive identity retains a production role with no documented exception or active owner. | Account activity, role, HR, and exception-search records collected during September 2026 UTC. |
| Evidence integrity | Evidence window |
| 4/4 sources verified · chain preserved | September 2026 UTC · demo source records |
| Impossible-travel authentication | Sign-in location records |
| Atlanta and Bucharest sign-ins occurred 14 minutes apart. | Observed sign-in records: Atlanta and Bucharest; 14-minute interval during September 2026 UTC. |
| New MFA method registered | Authentication-method record |
| Authenticator added from an unmanaged device. | Observed authenticator-registration record with an unmanaged-device attribute. |
| Bulk SharePoint download | SharePoint download records |
| 312 files downloaded after the second sign-in. | Observed 312 file-download entries after the second sign-in during September 2026 UTC. |
| Malicious infrastructure match | Threat-feed records |
| Source IP appears in two independent threat feeds. | Observed source-IP entries in two threat-feed records during September 2026 UTC. |
| Affected version confirmed | Inventory version observed |
| Package inventory matches the vulnerable range. | Collected package-version and advisory-range records. |
| External path verified | Service response observed |
| Gateway responds on the affected service port. | Collected gateway service-response record. |
| Known exploitation | Catalog entry observed |
| The vulnerability appears in CISA KEV. | Collected a CISA KEV catalog reference. |
| Production dependency mapped | Dependency record collected |
| Gateway supports customer authentication traffic. | Observed customer-authentication dependency in CMDB record. |
| Dormant privileged account | Account activity observations |
| No interactive use in 93 days | Activity records · 2026-06-12–2026-09-13 UTC |
| Last successful sign-in occurred June 12. | Most recent sign-in in collected records: 2026-06-12 UTC. |
| Privileged role remains active | Role assignment observed |
| Identity retains Production Administrator. | Observed Production Administrator assignment in the collected record. |
| No current HR assignment | HR record collected |
| User moved to an unrelated cost center. | Observed cost-center change in the HR record. |
| No exception on file | Exception search observed |
| Policy exception search returned no result. | Observed no entries in the collected exception-search result. |
| SOC Agent · Threat investigation | SOC Agent · Observations |
| Vulnerability Agent · Exposure management | Vulnerability Agent · Observations |
| Identity Agent · Access assurance | Identity Agent · Observations |
| Compliance Agent · Continuous assurance | Compliance Agent · Evidence collection |
| Security Engineering Agent · Defense improvement | Security Engineering Agent · Observations |
| Correlated identity, endpoint, cloud, and network evidence; flagged compromise indicators; proposed containment for human review. | Observed identity, endpoint, cloud, and network records; pending review. |
| Analyzed exposure, exploit activity, asset criticality, compensating controls, and remediation risk; prioritized findings; recommended a patch review. | Collected exposure, exploit-reference, asset, and control records; pending review. |
| Flagged risky sign-ins, privilege creep, stale identities, and access conflicts; recommended an access review. | Collected sign-in, privilege, account-activity, and access records; pending review. |
| Tested control criteria; validated evidence for control mappings; flagged gaps; proposed an evidence review. | Collected evidence for control criteria; pending review. |
| Analyzed detection coverage and change impact; tested rule criteria; proposed a detection change and rollback procedure. | Collected detection-rule and change-impact records; pending review. |
| Correlated four compromise signals. | Collected sign-in and download records during September 2026 UTC. |
| Prioritized external exposure and KEV evidence. | Collected exposure and KEV records; pending review. |
| Validated evidence for control criteria. | Collected evidence for control criteria. |
| Analyzed detection coverage. | Collected detection records; pending review. |
| Flagged dormant privileged access. | Observed account activity and entitlement records; pending review. |
| SOC Agent correlated 4 signals | SOC Agent collected signal records · September 2026 UTC |
| Identity Agent proposed session revocation | Identity Agent collected authentication records · September 2026 UTC |
| Vulnerability Agent prioritized CVE | Vulnerability Agent collected CVE records · September 2026 UTC |
| Compliance Agent validated evidence for SOC 2 CC6.1 | Compliance Agent collected SOC 2 CC6.1 evidence · September 2026 UTC |
| Engineering Agent proposed a rule | Engineering Agent observed a rule proposal · September 2026 UTC |
| Proposed identity containment for human review. | Collected observations; response proposal pending review. |
| Human approval required by IAM-IR-004; no session change. | Collected observations; decision pending review under IAM-IR-004. |
| Recommended patch review based on exposure and KEV evidence. | Collected exposure and KEV evidence; pending review. |
| Proposed human review of the control evidence. | Collected control evidence; pending review. |
| Proposed Sentinel detection mapped to ATT&CK T1078. | Observed Sentinel rule proposal with ATT&CK T1078 reference. |
| notify('3 items need your review.') | notify('Case observations · September 2026 UTC.') |
| 3 Active incidents 12 Critical exposures 326 Alerts analyzed 99.2% Procedure compliance | Control records · September 2026 UTC Not assessed first |
| 87 / 100 POSTURE | Cycle · September 2026 UTC |
| 3 | i |
| Severity Confidence | Assessment Window |
| Critical 97% | Pending review September 2026 UTC |
| score:'97%', | (removed) |
| High 94% | Pending review September 2026 UTC |
| score:'94%', | (removed) |
| Medium 91% | Pending review September 2026 UTC |
| score:'91%', | (removed) |
| 97% | (removed) |
| document.querySelector('#verdict-score').textContent=c.score; | (removed) |
| ✓ | · |
| ✓ | i |
| Action record severity: critical / high / medium | Pending review (unassessed proposal metadata withheld) |

## New computed and assessment-interface strings

- {in_scope} controls in scope. {tested} tested this cycle, {passed} passed, {failed} failed, {not_assessed} not yet tested.
- Not yet tested · 2026-09-01–2026-10-01 UTC
- Tested · 2026-09-01–2026-10-01 UTC
- Passed · 2026-09-01–2026-10-01 UTC
- Failed · 2026-09-01–2026-10-01 UTC
- Control records · September 2026 UTC
- Not assessed first
- Control record
- Close control record
- Session-only demo. Assessor identities are self-reported, not authenticated. Refresh resets records.
- Evidence source
- Record collected evidence
- Assessor identity (unverified demo input)
- Assessment rationale
- Record tested pass
- Record tested fail
- Record approved exception
- Evidence collection is not a test. An approved exception is not a pass.
- Sign-in review
- Exposure review
- Access review
- SOC 2 CC6.1 evidence
- Detection review
- Demo observation record
- Not assessed
- Evidence collected · pending review
- Tested pass
- Tested fail
- Exception approved
- {status} · {assessor} · {assessed_at} · cycle September 2026 UTC
- Evidence collected. Pending review.
- Assessment record added to this session.

## Model validation strings

- Unexpected control field
- Invalid cycle
- Unexpected evidence field
- Duplicate evidence
- Timestamp outside assessment cycle
- Human review capability required
- Invalid assessment status
- Evidence collection required before assessment
- Unexpected assessment field
- Assessment precedes evidence
- Unknown control
- Duplicate control
- {field} is required
- {field} must be a UTC timestamp

## Verification and limits

54 automated checks pass across action and control models. Coverage aggregation, cycle bounds, absence of implicit pass, assessor requirements, restricted agent capabilities, conclusion suppression, immutable records, unknown-first ordering, forbidden copy, and UI syntax are checked. No live browser or WebMCP runtime QA was performed.

This is still a session-only static prototype. Identities are explicitly unverified demo input, not authenticated authorization. No durable audit store or production identity service has been added. No outbound-system execution is implemented.

