# Project rules

Read HANDOFF.md before changing the application.

## Hard constraints

- No agent ever executes a security response. The application has no external-system writer. Execution is recorded as a human attestation, never performed.
- Preserve AgentAction fields, enum and model-layer transition checks. Approved requires an approver and decision timestamp. Executed may follow only approved. Never bypass these through UI or agent tools.
- Preserve ControlStatus: not_assessed, evidence_collected, tested_pass, tested_fail, exception_approved. No evidence defaults to not_assessed, never implicit pass.
- Agents can collect evidence only. Test/exception conclusions require the human review capability, assessor and assessed_at. No fabricated identities.
- Show observations, not agent verdicts. Forbidden agent-generated wording: compliant, effective, secure, within policy, validated, operating correctly, all clear, nominal. The newer prohibition on validated overrides the earlier allowed phrase "validated evidence for".
- Never describe agent work as revoked, disabled, isolated, blocked, applied, remediated, fixed, or resolved.
- Every metric needs its time window. Unknown coverage has higher visibility and sort priority than failures.
- Individual conclusions require adjacent assessor and timestamp. Do not treat exceptions or collected evidence as passed tests.
- Keep the headline computed: "{in_scope} controls in scope. {tested} tested this cycle, {passed} passed, {failed} failed, {not_assessed} not yet tested."
- The current UI is an explicitly session-only demo. Never present self-reported identities as authenticated people, or browser memory as a durable audit store.

## Workflow

- Run `node --test action-model.test.mjs control-model.test.mjs finding-model.test.mjs`.
- src/ is authored source with no build step. No agent should treat it as generated output.
- Update copy ledgers for copy changes. Historical diff text is not active application copy.
- This project has no deployment pipeline. No agent may deploy, publish, or host it.
- Do not provision paid services, introduce external writers or connect real customer data without explicit authorization.
- Never commit API keys, Git tokens, .env values, customer logs or local credentials.
