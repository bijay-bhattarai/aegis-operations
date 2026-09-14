"""Reproduce the Entra finding seeds and their independently reported scores."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

import identity_agent

ROOT = Path(__file__).resolve().parent
SNAPSHOT = ROOT / "data" / "entitlement-snapshot.csv"
HASH_PIN = ROOT / "data" / "entitlement-snapshot.sha256"
ANSWER_KEY = ROOT / "data" / "identity-answer-key.json"
FINDINGS_OUTPUT = ROOT / "data" / "entra-findings.json"
RESULTS_OUTPUT = ROOT / "data" / "identity-pipeline-results.json"
SEED_OUTPUT = ROOT / "src" / "entra-finding-seeds.mjs"
README = ROOT / "README.md"
SOURCE_LABEL = "data/entitlement-snapshot.csv"
RESULTS_START = "<!-- identity-results:start -->"
RESULTS_END = "<!-- identity-results:end -->"

SNAPSHOT_EVIDENCE_ID = "ENTRA-SNAPSHOT-2026-08-23"
ARTIFACT_LOCATOR = "artifact://entra/entitlement-snapshot-2026-08-23"
QUEUE_RULES = {"R01": "priority-review", "R02": "standard-review",
               "R03": "priority-review", "R04": "standard-review",
               "R05": "standard-review"}
MATRIX = {
    ("R01", "critical"): ("high", "high"),
    ("R01", "high"): ("high", "medium"),
    ("R02", "medium"): ("medium", "medium"),
    ("R03", "high"): ("medium", "high"),
    ("R04", "high"): ("medium", "high"),
    ("R05", "medium"): ("high", "low"),
}


class PipelineError(RuntimeError):
    pass


def canonical_json(value):
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def fingerprint(finding):
    return (finding["subject"]["display_name"], finding["rule_id"], finding["title"])


def read_inputs():
    pin_parts = HASH_PIN.read_text(encoding="utf-8").strip().split()
    if len(pin_parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", pin_parts[0]):
        raise PipelineError(f"Malformed SHA-256 pin: {HASH_PIN.relative_to(ROOT)}")
    expected_hash = pin_parts[0]
    actual_hash = hashlib.sha256(SNAPSHOT.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise PipelineError(
            f"Snapshot SHA-256 mismatch for {SOURCE_LABEL}: expected {expected_hash}, got {actual_hash}"
        )
    answer_key = json.loads(ANSWER_KEY.read_text(encoding="utf-8"))
    _, users = identity_agent.load(SNAPSHOT)
    timestamps = {user["snapshot"] for user in users.values()}
    if len(timestamps) != 1:
        raise PipelineError(f"Snapshot contains {len(timestamps)} distinct timestamps")
    return expected_hash, answer_key, users, timestamps.pop()


def assign_ids(raw_findings, answer_key):
    known = {
        (entry["subject"], entry["rule_id"], entry["title"]): entry["finding_id"]
        for entry in answer_key["known_defects"]
    }
    used = set(known.values())
    result = []
    for finding in raw_findings:
        key = fingerprint(finding)
        finding_id = known.get(key)
        if finding_id is None:
            material = "\x1f".join(key).encode("utf-8")
            finding_id = "IAM-X-" + hashlib.sha256(material).hexdigest()[:12].upper()
            if finding_id in used:
                raise PipelineError(f"Deterministic finding ID collision: {finding_id}")
        used.add(finding_id)
        result.append((finding_id, finding))
    return sorted(result, key=lambda pair: pair[0])


def structured_facts(finding):
    facts = []
    for item in finding["evidence"]:
        key, value = item.split("=", 1)
        if key in {"department", "department_attribute", "owning_department", "title"}:
            continue
        if key == "account_enabled":
            value = value.lower() == "true"
        facts.append({"key": key, "value": value})
    return facts


def to_aegis_findings(raw_findings, answer_key, snapshot_at):
    seeds = []
    for finding_id, raw in assign_ids(raw_findings, answer_key):
        try:
            likelihood, impact = MATRIX[(raw["rule_id"], raw["severity"])]
        except KeyError as error:
            raise PipelineError(
                f"No reviewed risk-matrix mapping for {raw['rule_id']} {raw['severity']}"
            ) from error
        subject = raw["subject"]
        seeds.append({
            "finding_id": finding_id,
            "rule_id": raw["rule_id"],
            "title": raw["title"],
            "subject": {
                "type": "user",
                "id": {"namespace": "microsoft_entra_id", "value": subject["object_id"]},
                "label": subject["display_name"],
                "details": {
                    "principal_name": subject["upn"],
                    "department": subject["department"],
                    "job_title": subject["title"],
                    "privileged": subject["privileged"],
                },
            },
            "evidence_lines": structured_facts(raw),
            "control_refs": raw["control_refs"]["nist_800_53"],
            "severity_input": {"risk_matrix": {"likelihood": likelihood, "impact": impact}},
            "finding_type": "identity",
            "evidence_id": SNAPSHOT_EVIDENCE_ID,
            "created_at": snapshot_at,
            "agent_id": "identity",
        })
    return seeds


def ratio(matched, total):
    return {"value": matched / total if total else 0.0, "matched": matched, "total": total}


def score(raw_findings, answer_key):
    actual = {fingerprint(item): item for item in raw_findings}
    expected = {
        (item["subject"], item["rule_id"], item["title"]): item
        for item in answer_key["known_defects"]
    }
    matched = set(actual) & set(expected)
    severity_matches = sum(actual[key]["severity"] == expected[key]["severity"] for key in matched)
    by_subject = {item["subject"]["display_name"] for item in raw_findings}
    unexpected_controls = sorted(set(answer_key["control_cases"]) & by_subject)
    return {
        "recall": ratio(len(matched), len(expected)),
        "precision": ratio(len(matched), len(actual)),
        "severity_accuracy": ratio(severity_matches, len(matched)),
        "control_cases": {
            "result": "pass" if not unexpected_controls else "fail",
            "passed": len(answer_key["control_cases"]) - len(unexpected_controls),
            "total": len(answer_key["control_cases"]),
            "unexpected_findings": unexpected_controls,
        },
        "missed": [expected[key]["finding_id"] for key in sorted(set(expected) - set(actual))],
        "unexpected": [list(key) for key in sorted(set(actual) - set(expected))],
    }


def clone_users(users):
    return copy.deepcopy(users)


def perturbation_results(users, digest, baseline):
    perturbed = clone_users(users)
    cases = [
        ("R01", "Andre Kalu", "add ROLE-Store-Associate"),
        ("R02", "Lena Kowalski", "add ROLE-IT-SysAdmin"),
        ("R03", "Jonah Bricker", "add ROLE-Finance-AP and ROLE-Finance-Controller"),
        ("R04", "Colin Pruitt", "disable account and add retained entitlement"),
        ("R05", "Marisol Vega", "remove ROLE-Store-Associate"),
    ]
    perturbed["Andre Kalu"]["groups"].add("ROLE-Store-Associate")
    perturbed["Andre Kalu"]["roles"].add("ROLE-Store-Associate")
    perturbed["Lena Kowalski"]["groups"].add("ROLE-IT-SysAdmin")
    perturbed["Lena Kowalski"]["roles"].add("ROLE-IT-SysAdmin")
    perturbed["Jonah Bricker"]["groups"].update({"ROLE-Finance-AP", "ROLE-Finance-Controller"})
    perturbed["Jonah Bricker"]["roles"].update({"ROLE-Finance-AP", "ROLE-Finance-Controller"})
    perturbed["Colin Pruitt"]["enabled"] = False
    perturbed["Colin Pruitt"]["groups"].add("ROLE-Store-Associate")
    perturbed["Colin Pruitt"]["roles"].add("ROLE-Store-Associate")
    perturbed["Marisol Vega"]["groups"].discard("ROLE-Store-Associate")
    perturbed["Marisol Vega"]["roles"].discard("ROLE-Store-Associate")
    injected, _, _, _ = identity_agent.evaluate(perturbed, digest)
    baseline_keys = {fingerprint(item) for item in baseline}
    additions = [item for item in injected if fingerprint(item) not in baseline_keys]
    detected = {(item["rule_id"], item["subject"]["display_name"]) for item in additions}
    expected = {(rule, subject) for rule, subject, _ in cases}

    removed = clone_users(users)
    removed["Devon Reyes"]["groups"].discard("ROLE-IT-SysAdmin")
    removed["Devon Reyes"]["roles"].discard("ROLE-IT-SysAdmin")
    after_removal, _, _, _ = identity_agent.evaluate(removed, digest)
    target = ("Devon Reyes", "R01", "Store Operations user holds ROLE-IT-SysAdmin")
    after_keys = {fingerprint(item) for item in after_removal}
    side_effects = sorted((baseline_keys - {target}) ^ after_keys)
    return {
        "injected_defects": {
            "result": "pass" if detected == expected and len(additions) == 5 else "fail",
            "detected": len(detected & expected),
            "total": 5,
            "unexpected": [list(item) for item in sorted(detected - expected)],
            "cases": [{"rule_id": rule, "subject": subject, "mutation": mutation,
                       "detected": (rule, subject) in detected} for rule, subject, mutation in cases],
        },
        "known_defect_removal": {
            "result": "pass" if target not in after_keys and not side_effects else "fail",
            "removed_finding_id": "IAM-0004",
            "cleared": target not in after_keys,
            "side_effects": [list(item) for item in side_effects],
        },
    }


def render_seed(payload, digest):
    snapshot = json.dumps(payload["snapshot"], indent=2, ensure_ascii=False)
    findings = json.dumps(payload["findings"], indent=2, ensure_ascii=False)
    queues = json.dumps(payload["queue_rules"], indent=2, ensure_ascii=False)
    return f"""// GENERATED FILE. DO NOT EDIT.
// Source: {SOURCE_LABEL}
// SHA-256: {digest}
// Reproduce: python3 identity_agent.py

const deepFreeze=value=>{{if(value&&typeof value==='object'&&!Object.isFrozen(value)){{for(const child of Object.values(value))deepFreeze(child);Object.freeze(value);}}return value;}};

export const ENTRA_SNAPSHOT=deepFreeze({snapshot});
export const ENTRA_FINDING_SEEDS=deepFreeze({findings});
export const ENTRA_QUEUE_RULES=deepFreeze({queues});
"""


def results_block(results):
    score_data = results["answer_key"]
    perturb = results["perturbation"]
    pct = lambda part: f"{part['value']:.2f} ({part['matched']}/{part['total']})"
    return f"""{RESULTS_START}
## Identity pipeline results

The checked-in results are read from [`data/identity-pipeline-results.json`](data/identity-pipeline-results.json). Reproduce the snapshot verification, five rules, answer-key scoring, perturbation checks, Aegis output, and generated seed module with:

```sh
python3 identity_agent.py
```

| Check | Result |
|---|---:|
| Recall | {pct(score_data['recall'])} |
| Precision | {pct(score_data['precision'])} |
| Severity accuracy | {pct(score_data['severity_accuracy'])} |
| Control cases | {score_data['control_cases']['result'].upper()} ({score_data['control_cases']['passed']}/{score_data['control_cases']['total']}) |
| Five injected perturbations | {perturb['injected_defects']['result'].upper()} ({perturb['injected_defects']['detected']}/{perturb['injected_defects']['total']}) |
| Known-defect removal isolation | {perturb['known_defect_removal']['result'].upper()} |

These are separate measurements. The perturbation result is reported separately because answer-key performance on the tuning set alone is not independent evidence.
{RESULTS_END}"""


def update_readme(current, block):
    pattern = re.compile(re.escape(RESULTS_START) + r".*?" + re.escape(RESULTS_END), re.S)
    if pattern.search(current):
        return pattern.sub(block, current)
    marker = "\n## Included\n"
    if marker not in current:
        raise PipelineError("README.md has no insertion point for identity results")
    return current.replace(marker, "\n" + block + marker, 1)


def build():
    digest, answer_key, users, snapshot_at = read_inputs()
    raw, scoped, skipped, _ = identity_agent.evaluate(users, digest)
    seeds = to_aegis_findings(raw, answer_key, snapshot_at)
    snapshot = {
        "evidence_id": SNAPSHOT_EVIDENCE_ID,
        "source": "Microsoft Entra ID",
        "collected_by": {"type": "agent", "id": "identity"},
        "collected_at": snapshot_at,
        "artifact_ref": {
            "type": "export", "locator": ARTIFACT_LOCATOR,
            "content_hash": {"algorithm": "sha256", "value": digest},
            "verification_status": "unverified",
        },
    }
    payload = {"snapshot": snapshot, "findings": seeds, "queue_rules": QUEUE_RULES}
    results = {
        "snapshot": {"source": SOURCE_LABEL, "sha256": digest, "snapshot_at": snapshot_at},
        "scope": {"users_in_scope": scoped, "users_excluded": skipped},
        "answer_key": score(raw, answer_key),
        "perturbation": perturbation_results(users, digest, raw),
    }
    if results["answer_key"]["recall"]["value"] != 1 or results["answer_key"]["precision"]["value"] != 1:
        raise PipelineError("Answer-key scoring failed; generated artifacts were not written")
    if results["answer_key"]["severity_accuracy"]["value"] != 1:
        raise PipelineError("Severity accuracy failed; generated artifacts were not written")
    if results["answer_key"]["control_cases"]["result"] != "pass":
        raise PipelineError("Control-case check failed; generated artifacts were not written")
    if any(item["result"] != "pass" for item in results["perturbation"].values()):
        raise PipelineError("Perturbation check failed; generated artifacts were not written")
    readme = update_readme(README.read_text(encoding="utf-8"), results_block(results))
    return {
        FINDINGS_OUTPUT: canonical_json(payload),
        RESULTS_OUTPUT: canonical_json(results),
        SEED_OUTPUT: render_seed(payload, digest),
        README: readme,
    }, results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if generated files have drifted")
    args = parser.parse_args(argv)
    try:
        outputs, results = build()
        if args.check:
            drift = [path.relative_to(ROOT).as_posix() for path, expected in outputs.items()
                     if not path.exists() or path.read_text(encoding="utf-8") != expected]
            if drift:
                raise PipelineError("Generated files are stale: " + ", ".join(drift))
            print("Identity pipeline check passed: snapshot hash and generated files match.")
        else:
            for path, content in outputs.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="\n")
            print(f"Identity pipeline generated {len(outputs) - 1} artifacts from verified snapshot.")
        answer = results["answer_key"]
        perturb = results["perturbation"]
        print(f"Recall {answer['recall']['value']:.2f}; precision {answer['precision']['value']:.2f}; "
              f"severity accuracy {answer['severity_accuracy']['value']:.2f}; "
              f"control cases {answer['control_cases']['result'].upper()}.")
        print(f"Perturbations {perturb['injected_defects']['result'].upper()} "
              f"({perturb['injected_defects']['detected']}/5); removal isolation "
              f"{perturb['known_defect_removal']['result'].upper()}.")
        return 0
    except (OSError, ValueError, KeyError, PipelineError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
