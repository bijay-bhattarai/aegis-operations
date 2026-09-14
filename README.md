# Aegis Operations

Supervised security operations. Portable local prototype.

## Start locally

Prerequisites: Node.js 22+ for tests and Python 3 for the development-only static server.
No npm dependencies, API keys, or security-platform accounts are required.

From this folder:

```sh
node --test action-model.test.mjs control-model.test.mjs finding-model.test.mjs
python3 -m http.server 8000 --bind 127.0.0.1 --directory src
```

Open http://127.0.0.1:8000 in your browser. Stop the server with Ctrl+C.
Use HTTP rather than double-clicking index.html: the application uses ES modules.

## Continue with Codex

Open this folder as your local Codex project, or run `codex` from this folder.
Ask: "Read AGENTS.md and HANDOFF.md. Run the existing tests and review the implementation gaps before proposing the next change."

Official instructions:
- https://developers.openai.com/codex/cli
- https://developers.openai.com/codex/guides/agents-md

## Private GitHub repository

The export has no Git credentials and no GitHub remote.
Create a new PRIVATE repository named aegis-operations in your own account, without an initial README.
Then initialize Git in this folder and push to that repository using your normal authenticated Git tooling.
Do not publish this repository publicly without reviewing the source and historical copy ledgers.

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
## Included

- src/index.html: UI and demo records
- src/action-model.mjs: AgentAction state machine and restricted ports
- src/evidence-model.mjs: immutable evidence records and shared repository
- src/control-model.mjs: control assessment model and coverage
- identity_agent.py and identity_pipeline.py: deterministic Entra rules and the reproducible evidence-to-seed pipeline
- data/entitlement-snapshot.csv, its pinned SHA-256, the answer key, generated Aegis findings, and separate score results
- src/entra-finding-seeds.mjs: generated, committed runtime records; do not edit by hand
- Three Node test suites
- COPY_CHANGES.md and ASSESSMENT_CHANGES.md: before/after ledgers
- Source diffs: historical reference, not current requirements
- AGENTS.md and HANDOFF.md: continuing instructions and known limitations

This repository has no deployment manifest or pipeline. Run it locally using the instructions above.
