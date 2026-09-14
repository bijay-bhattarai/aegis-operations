# Aegis Operations

Aegis Operations is a local prototype for supervised security operations. Agents identify observations and propose actions; human reviewers assess controls and decide whether to approve or reject proposals. The application records those decisions and external execution attestations but never performs a security action. Its ten identity findings come from a hash-verified Microsoft Entra ID entitlement export, and their severity is computed from a versioned policy rather than asserted by the rule engine.

<!-- identity-results:start -->
## Identity pipeline results

The checked-in results are read from [`data/identity-pipeline-results.json`](data/identity-pipeline-results.json). Reproduce the snapshot verification, five rules, answer-key scoring, perturbation checks, Aegis output, and generated seed module with:

```sh
python3 identity_agent.py
```

| Check | Result |
|---|---:|
| Recall | 1.00 (10/10) |
| Precision | 1.00 (10/10) |
| Severity accuracy | 1.00 (10/10) |
| Control cases | PASS (2/2) |
| Five injected perturbations | PASS (5/5) |
| Known-defect removal isolation | PASS |

These are separate measurements. The perturbation result is reported separately because answer-key performance on the tuning set alone is not independent evidence.
<!-- identity-results:end -->

## Run locally

Node.js 22+ is required for tests, and Python 3 is required for the local static server and identity pipeline. The repository has no npm dependencies and requires no API keys or security-platform accounts.

From the repository root, run:

```sh
node --test
python3 -m http.server 8000 --bind 127.0.0.1 --directory src
```

Open http://127.0.0.1:8000 in a browser. Use HTTP because the application uses ES modules; stop the server with Ctrl+C.

## Repository contents

- `src/index.html`: the hash-routed user interface and session records
- `src/action-model.mjs`: append-only AgentAction lifecycle and restricted ports
- `src/evidence-model.mjs`: immutable evidence records and shared repository
- `src/control-model.mjs`: control assessments and coverage calculations
- `src/finding-model.mjs`: finding lifecycle, severity, SLA, and projections
- `src/approval-queue-model.mjs`, `src/audit-model.mjs`, `src/route-model.mjs`, and `src/demo-overview-model.mjs`: derived views and navigation
- `src/identity-model.mjs`: shared person-versus-agent identity checks with NFKC normalization and zero-width stripping, used by the control and action models to prevent agent IDs from being recorded as human assessors or approvers
- `identity_agent.py` and `identity_pipeline.py`: deterministic Entra rules and the reproducible evidence-to-seed pipeline
- `data/entitlement-snapshot.csv`: the source export, accompanied by its pinned SHA-256, answer key, generated Aegis findings, and separate score results
- `src/entra-finding-seeds.mjs`: generated and committed runtime records; regenerate it through the pipeline rather than editing it
- `*.test.mjs`: Node test suites covering the domain models, generated-data drift, and interface constraints
- `COPY_CHANGES.md`, `ASSESSMENT_CHANGES.md`, `AGENTS.md`, and `HANDOFF.md`: copy history, project rules, and implementation limitations

## What this is not

This is not a production security system or a durable audit store. All application state is session-only, with no backend or persistence. Reviewer identities are supplied by the reviewer and are not authenticated. Artifact hashes are recorded, but there is no artifact resolver to retrieve or independently verify their contents. The repository has no deployment manifest or deployment pipeline and is intended to run locally.
