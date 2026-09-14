"""
Identity Agent rule engine.

Deterministic rules only. No model involvement in any verdict.
Input: entitlement snapshot CSV exported via Microsoft Graph.
Output: findings in the shared Aegis finding schema.
"""
import csv, io, hashlib
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
        u.update(id=r["UserId"], name=r["DisplayName"], upn=r["UserPrincipalName"],
                 dept=r["Department"], title=r["JobTitle"],
                 enabled=r["AccountEnabled"] == "True",
                 snapshot=r["SnapshotDateUTC"])
        if r["GroupDisplayName"]:
            u["groups"].add(r["GroupDisplayName"])
    for u in users.values():
        u["roles"] = {g for g in u["groups"] if g.startswith("ROLE-")}
    return rows, dict(users)

def evaluate(users, digest):
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
                    "subject": {"object_id": u["id"], "display_name": u["name"], "upn": u["upn"],
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

def run(path):
    _, users = load(path)
    with open(path, "rb") as source:
        digest = hashlib.sha256(source.read()).hexdigest()
    return evaluate(users, digest)

if __name__ == "__main__":
    from identity_pipeline import main
    raise SystemExit(main())
