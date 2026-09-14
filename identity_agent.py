"""
Identity Agent rule engine.

Deterministic rules only. No model involvement in any verdict.
Input: entitlement snapshot CSV exported via Microsoft Graph.
Output: findings in the shared Aegis finding schema.
"""
import csv, io, json, hashlib
from collections import defaultdict

# ---------------------------------------------------------------- policy

# Job function to expected role group. Titles absent from this map have no
# defined role entitlement, so provisioning completeness does not apply.
EXPECTED_ROLE = {
    "Store Associate":        "ROLE-Store-Associate",
    "HR Coordinator":         "ROLE-HR-Coordinator",
    "Controller":             "ROLE-Finance-Controller",
    "Systems Administrator":  "ROLE-IT-SysAdmin",
    "Helpdesk Technician":    "ROLE-IT-Helpdesk",
    "Accounts Payable Clerk": "ROLE-Finance-AP",
}

# Role group to the department that owns it.
ROLE_DEPARTMENT = {
    "ROLE-Store-Associate":     "Store Operations",
    "ROLE-HR-Coordinator":      "HR",
    "ROLE-Finance-AP":          "Finance",
    "ROLE-Finance-Controller":  "Finance",
    "ROLE-IT-Helpdesk":         "IT",
    "ROLE-IT-SysAdmin":         "IT",
}

PRIVILEGED_ROLES = {"ROLE-IT-SysAdmin", "ROLE-Finance-Controller"}

# Toxic combinations. One person must not both enter and approve a payment.
SOD_PAIRS = [("ROLE-Finance-AP", "ROLE-Finance-Controller")]

# Roles that supersede one another within a career path. Holding both means
# the prior one was never removed.
SUPERSEDED_BY = {"ROLE-IT-SysAdmin": ["ROLE-IT-Helpdesk"]}

# Accounts outside review scope: no department, no title, no entitlements.
# Administrative and break-glass identities are governed separately.
def out_of_scope(u):
    return not u["dept"] and not u["title"] and not u["groups"]

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

def bump(sev, n):
    i = max(0, min(len(SEVERITY_ORDER) - 1, SEVERITY_ORDER.index(sev) + n))
    return SEVERITY_ORDER[i]

# ---------------------------------------------------------------- rules

def r01_cross_department_role(u):
    """Role group belonging to a department other than the user's."""
    out = []
    for g in u["roles"]:
        owner = ROLE_DEPARTMENT.get(g)
        if owner and u["dept"] and owner != u["dept"]:
            if g in [s for sup in SUPERSEDED_BY.values() for s in sup] and \
               any(k in u["roles"] for k in SUPERSEDED_BY):
                continue  # handled by R02 as retained prior role
            base = "high"
            inputs = ["base:high"]
            if g in PRIVILEGED_ROLES:
                base = bump(base, 1); inputs.append("privileged_role:+1")
            out.append(dict(
                rule_id="R01", severity=base, severity_inputs=inputs,
                title=f"{u['dept']} user holds {g}",
                evidence=[f"department={u['dept']}", f"group={g}",
                          f"owning_department={owner}"],
                control_refs={"nist_800_53": ["AC-6", "AC-6(1)"],
                              "cis_v8": ["6.8"], "csf_2_0": ["PR.AA-05"]},
                action=f"Remove {g} or document an approved exception with an owner and expiry."))
    return out

def r02_retained_prior_role(u):
    """Superseded role still attached after a role change."""
    out = []
    for current, priors in SUPERSEDED_BY.items():
        if current in u["roles"]:
            for p in priors:
                if p in u["roles"]:
                    out.append(dict(
                        rule_id="R02", severity="medium", severity_inputs=["base:medium"],
                        title=f"Retains both {p} and {current}",
                        evidence=[f"group={p}", f"group={current}", f"title={u['title']}"],
                        control_refs={"nist_800_53": ["AC-2(3)", "AC-6"],
                                      "cis_v8": ["6.2"], "csf_2_0": ["PR.AA-05"]},
                        action=f"Remove {p}; the role was superseded by {current}."))
    return out

def r03_sod_conflict(u):
    out = []
    for a, b in SOD_PAIRS:
        if a in u["roles"] and b in u["roles"]:
            out.append(dict(
                rule_id="R03", severity="high", severity_inputs=["base:high"],
                title=f"Holds toxic pair {a} and {b}",
                evidence=[f"group={a}", f"group={b}", f"department={u['dept']}"],
                control_refs={"nist_800_53": ["AC-5"], "cis_v8": ["6.8"],
                              "csf_2_0": ["PR.AA-05"]},
                action="Remove one role, or document a compensating control with a named approver and review date."))
    return out

def r04_disabled_with_entitlements(u):
    if u["enabled"] or not u["groups"]:
        return []
    sev = "high"
    inputs = ["base:high"]
    if any(g in PRIVILEGED_ROLES for g in u["roles"]):
        sev = bump(sev, 1); inputs.append("privileged_role:+1")
    return [dict(
        rule_id="R04", severity=sev, severity_inputs=inputs,
        title="Disabled account retains group entitlements",
        evidence=[f"account_enabled=False"] + [f"group={g}" for g in sorted(u["groups"])]
                 + [f"department_attribute={u['dept'] or '(cleared)'}"],
        control_refs={"nist_800_53": ["AC-2(1)", "AC-2(4)"], "cis_v8": ["5.3"],
                      "csf_2_0": ["PR.AA-01"]},
        action="Complete offboarding: revoke sessions, remove role groups, clear the department attribute.")]

def r05_missing_expected_role(u):
    if not u["enabled"]:
        return []
    expected = EXPECTED_ROLE.get(u["title"])
    if expected and expected not in u["roles"]:
        return [dict(
            rule_id="R05", severity="medium", severity_inputs=["base:medium"],
            title=f"Missing expected {expected.replace('ROLE-','').replace('-',' ')} role",
            evidence=[f"title={u['title']}", f"expected_group={expected}",
                      f"assigned_roles={','.join(sorted(u['roles'])) or '(none)'}"],
            control_refs={"nist_800_53": ["AC-2"], "cis_v8": ["5.3"],
                          "csf_2_0": ["PR.AA-01"]},
            action="Assign the expected role after manager or role-owner validation. Indicates a joiner verification step without a pass condition.")]
    return []

RULES = [r01_cross_department_role, r02_retained_prior_role, r03_sod_conflict,
         r04_disabled_with_entitlements, r05_missing_expected_role]

# ---------------------------------------------------------------- engine

def load(path):
    rows = list(csv.DictReader(io.open(path, encoding="utf-8-sig")))
    users = defaultdict(lambda: {"groups": set()})
    for r in rows:
        u = users[r["DisplayName"]]
        u.update(name=r["DisplayName"], upn=r["UserPrincipalName"],
                 dept=r["Department"], title=r["JobTitle"],
                 enabled=r["AccountEnabled"] == "True",
                 snapshot=r["SnapshotDateUTC"])
        if r["GroupDisplayName"]:
            u["groups"].add(r["GroupDisplayName"])
    for u in users.values():
        u["roles"] = {g for g in u["groups"] if g.startswith("ROLE-")}
    return rows, dict(users)

def run(path):
    rows, users = load(path)
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    findings, scoped, skipped = [], 0, []
    n = 0
    for name in sorted(users):
        u = users[name]
        if out_of_scope(u):
            skipped.append(name); continue
        scoped += 1
        for rule in RULES:
            for f in rule(u):
                n += 1
                findings.append({
                    "finding_id": f"IAM-{n:04d}",
                    "rule_id": f["rule_id"],
                    "title": f["title"],
                    "subject": {"display_name": u["name"], "upn": u["upn"],
                                "department": u["dept"], "title": u["title"],
                                "privileged": bool(u["roles"] & PRIVILEGED_ROLES)},
                    "evidence": f["evidence"],
                    "control_refs": f["control_refs"],
                    "severity": f["severity"],
                    "severity_inputs": f["severity_inputs"],
                    "recommended_action": f["action"],
                    "requires_human_approval": True,
                    "confidence": "high",
                    "source_dataset": f"entitlement-snapshot.csv sha256:{digest[:16]}",
                    "snapshot_at": u["snapshot"],
                })
    return findings, scoped, skipped, digest

# ---------------------------------------------------------------- scoring

# Answer key from the published findings report.
GROUND_TRUTH = {
    "Devon Reyes":     "critical",
    "Peter Nkemelu":   "high",
    "Rashid Malik":    "high",
    "Terrence Boyd":   "high",
    "Owen Fitzgerald": "medium",
    "Amara Osei":      "medium",
    "Bea Lindqvist":   "medium",
    "Camila Restrepo": "medium",
    "Priya Raman":     "medium",
    "Tomas Njoku":     "medium",
}
CONTROL_CASES = ["Ines Duarte", "Colin Pruitt"]

def score(findings):
    found = defaultdict(list)
    for f in findings:
        found[f["subject"]["display_name"]].append(f)

    tp = [n for n in GROUND_TRUTH if n in found]
    fn = [n for n in GROUND_TRUTH if n not in found]
    fp = [n for n in found if n not in GROUND_TRUTH]
    ctrl_fp = [n for n in CONTROL_CASES if n in found]

    recall = len(tp) / len(GROUND_TRUTH)
    precision = len(tp) / len(found) if found else 0.0
    sev_match = [n for n in tp if any(f["severity"] == GROUND_TRUTH[n] for f in found[n])]
    return dict(found=found, tp=tp, fn=fn, fp=fp, ctrl_fp=ctrl_fp,
                recall=recall, precision=precision,
                sev_accuracy=len(sev_match) / len(tp) if tp else 0.0,
                sev_match=sev_match)

if __name__ == "__main__":
    findings, scoped, skipped, digest = run("snap.csv")
    s = score(findings)

    print("=" * 68)
    print("IDENTITY AGENT v1.0  —  scored against the published answer key")
    print("=" * 68)
    print(f"dataset sha256 : {digest[:32]}...")
    print(f"users in scope : {scoped}   (excluded {len(skipped)}: {', '.join(skipped)})")
    print(f"findings       : {len(findings)} across {len(s['found'])} users")
    print()

    print(f"{'USER':18} {'SEV':9} {'RULE':6} TITLE")
    print("-" * 68)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda x: (order[x["severity"]], x["subject"]["display_name"])):
        print(f"{f['subject']['display_name']:18} {f['severity']:9} {f['rule_id']:6} {f['title']}")

    print()
    print("=" * 68)
    print("SCORE")
    print("=" * 68)
    print(f"recall            {s['recall']:.2f}   ({len(s['tp'])}/{len(GROUND_TRUTH)} known defects detected)")
    print(f"precision         {s['precision']:.2f}   ({len(s['tp'])}/{len(s['found'])} flagged users are true defects)")
    print(f"severity accuracy {s['sev_accuracy']:.2f}   ({len(s['sev_match'])}/{len(s['tp'])} match the reported severity)")
    print(f"control cases     {'PASS' if not s['ctrl_fp'] else 'FAIL'}   ({', '.join(CONTROL_CASES)} correctly produced no finding)"
          if not s["ctrl_fp"] else f"control cases     FAIL   flagged: {s['ctrl_fp']}")
    if s["fn"]: print(f"missed            {s['fn']}")
    if s["fp"]: print(f"false positives   {s['fp']}")

    json.dump(findings, open("findings.json", "w"), indent=2)
    print("\nfindings.json written")
