# Microsoft Entra ID finding severity rules

These rules translate the deterministic identity engine outputs into the Aegis general risk matrix. The matrix ranks `low=1`, `medium=2`, and `high=3`, then maps the likelihood-plus-impact score through the versioned `aegis-risk-matrix-severity-1` policy: 2 low, 3–4 medium, 5 high, and 6 critical. Severity remains computed by the Finding model rather than copied from the engine's output band.

| Rule outcome | Likelihood | Impact | Computed band | Reasoning |
|---|---|---|---|---|
| R01 cross-department privileged role | high | high | critical | The entitlement crosses an ownership boundary and grants privileged authority, making both misuse likelihood and potential harm high. |
| R01 cross-department non-privileged role | high | medium | high | The ownership mismatch makes inappropriate access likely, while the non-privileged role limits the expected impact. |
| R02 retained superseded role | medium | medium | medium | The stale role is a real excess entitlement, but it remains within a documented career path and does not by itself establish broad or privileged misuse. |
| R03 separation-of-duties conflict | medium | high | high | Exploitation requires use of the conflicting duties, while the ability to both initiate and approve a payment creates high impact. |
| R04 disabled account retains entitlements | medium | high | high | The lab runbook states that disabling an account blocks new sign-ins but does not revoke existing refresh tokens, so a live session can survive the disable. Continued access is plausible and retained entitlements can have high impact. |
| R05 missing expected role | high | low | medium | The expected access is absent, so the operational harm is likely: the user cannot do their job. This is the only rule whose harm is operational rather than excessive access and must not later be rescored as an access-risk finding. |

No severity modifier is cited. This is deliberate: the snapshot does not evidence regulated data, broad scope, or a compensating control. The runtime records therefore omit the optional `modifiers` field instead of storing empty placeholder arrays.

The snapshot is recorded once as `ENTRA-SNAPSHOT-2026-08-23`. All ten findings reference that global evidence ID. R01 and R03 route to `priority-review`; R02, R04, and R05 route to `standard-review`.

Each identity finding records its subject as a `user`, keyed by the Microsoft Entra object ID from the snapshot. Display name, principal name, department, job title, and privileged-role context are immutable subject attributes on the active identified event. Rule observations are separate structured key/value facts: expected and assigned roles for R05, relevant group memberships for R01–R03, and account state plus retained groups for R04. Subject attributes are not repeated in those facts.
