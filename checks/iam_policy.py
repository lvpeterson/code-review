"""AWS IAM / resource-policy document checks (POL-xxx).

Works on a plain Python dict in IAM JSON shape, so the same rules run over:
  * standalone policy .json files (identity policies, S3 bucket policies,
    KMS key policies, role trust policies, SQS/SNS policies),
  * Terraform `policy = jsonencode({...})` / heredoc JSON values,
  * Terraform `data "aws_iam_policy_document"` blocks (converted by
    checks/terraform.py into the same shape).

Each check returns a PolicyIssue tied to a statement index (or -1 for a
whole-document issue); callers turn that into a file/line.

Wildcard matching follows IAM's own semantics: "iam:Put*" in a policy grants
iam:PutRolePolicy, so privilege-escalation detection matches the policy's
action *pattern* against each known-dangerous action, not string equality.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, Optional

# Actions that let a principal grant itself (or a role it controls) more
# permissions -- the well-known AWS IAM privilege-escalation paths.
PRIVESC_ACTIONS = [
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:PassRole",
    "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy",
    "iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy",
    "iam:AddUserToGroup", "iam:UpdateAssumeRolePolicy", "iam:PutUserPermissionsBoundary",
    "iam:DeleteUserPermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
    "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:CreateFunction",
    "lambda:AddPermission", "glue:UpdateDevEndpoint", "glue:CreateDevEndpoint",
    "cloudformation:CreateStack", "cloudformation:UpdateStack", "ec2:RunInstances",
    "ssm:SendCommand", "ssm:StartSession", "sts:AssumeRole", "codebuild:StartBuild",
    "codebuild:UpdateProject", "datapipeline:CreatePipeline",
]

# Reads that hand back data or key material -- dangerous on Resource "*".
SENSITIVE_READ_ACTIONS = [
    "s3:GetObject", "secretsmanager:GetSecretValue", "kms:Decrypt", "kms:GenerateDataKey",
    "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "dynamodb:Scan",
    "dynamodb:Query", "dynamodb:GetItem", "rds:DownloadDBLogFilePortion", "ec2:GetPasswordData",
    "lambda:GetFunction", "logs:GetLogEvents", "sqs:ReceiveMessage",
]

_READ_ONLY_PREFIXES = ("get", "list", "describe", "head", "view", "lookup", "search", "batchget", "query", "scan", "select")
_OIDC_HOSTS = re.compile(r"(?i)token\.actions\.githubusercontent\.com|gitlab|oidc|app\.terraform\.io|bitbucket")


@dataclass
class PolicyIssue:
    id: str
    severity: str
    title: str
    note: str
    statement_index: int  # -1 = whole document
    confidence: Optional[str] = None


def as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def statements(doc: Any) -> list[dict]:
    if not isinstance(doc, dict):
        return []
    return [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]


def looks_like_policy(doc: Any) -> bool:
    sts = statements(doc)
    return bool(sts) and all("Effect" in s for s in sts)


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), str(pattern).lower())


def _principals(stmt: dict) -> list[str]:
    p = stmt.get("Principal")
    if p is None:
        return []
    if isinstance(p, str):
        return [p]
    if isinstance(p, dict):
        out = []
        for _, v in p.items():
            out.extend(str(x) for x in as_list(v))
        return out
    return [str(x) for x in as_list(p)]


def _principal_types(stmt: dict) -> dict[str, list[str]]:
    p = stmt.get("Principal")
    if isinstance(p, dict):
        return {str(k): [str(x) for x in as_list(v)] for k, v in p.items()}
    if isinstance(p, str):
        return {"*": [p]}
    return {}


def _condition_keys(stmt: dict) -> dict[str, list[str]]:
    """{lowercased condition key: [values]} across every operator."""
    out: dict[str, list[str]] = {}
    cond = stmt.get("Condition")
    if not isinstance(cond, dict):
        return out
    for _op, body in cond.items():
        if not isinstance(body, dict):
            continue
        for key, vals in body.items():
            out.setdefault(str(key).lower(), []).extend(str(v) for v in as_list(vals))
    return out


def _is_wild_principal(value: str) -> bool:
    return value.strip() == "*"


def check_policy(doc: Any) -> list[PolicyIssue]:
    issues: list[PolicyIssue] = []
    if not isinstance(doc, dict):
        return issues

    version = doc.get("Version")
    if version is None or str(version) == "2008-10-17":
        issues.append(PolicyIssue(
            "POL-011", "low", "Policy document missing Version 2012-10-17",
            "Without \"Version\": \"2012-10-17\" IAM falls back to the 2008 grammar, where "
            "policy variables like ${aws:username} are treated as literal strings -- any "
            "condition or resource scoped with one silently stops matching what was intended.",
            -1,
        ))

    sts = statements(doc)
    is_bucket_policy = any(
        any(str(r).startswith("arn:aws:s3:::") for r in as_list(s.get("Resource")))
        and s.get("Principal") is not None
        for s in sts
    )

    for idx, s in enumerate(sts):
        effect = str(s.get("Effect", "")).lower()
        if effect != "allow":
            continue
        actions = [str(a) for a in as_list(s.get("Action"))]
        resources = [str(r) for r in as_list(s.get("Resource"))]
        conds = _condition_keys(s)
        res_star = "*" in resources
        act_star = any(a in ("*", "*:*") for a in actions)

        if "NotAction" in s or "NotResource" in s:
            issues.append(PolicyIssue(
                "POL-007", "medium", "Allow with NotAction/NotResource",
                "Allow + NotAction grants every action except the listed ones (including any "
                "AWS adds in future); Allow + NotResource grants on every resource except the "
                "listed ones. Rewrite as an explicit allow-list.",
                idx,
            ))

        if act_star and res_star:
            issues.append(PolicyIssue(
                "POL-001", "high", "Full administrator access (Action \"*\" on Resource \"*\")",
                "This statement grants every action on every resource -- equivalent to "
                "AdministratorAccess. Scope it to the specific actions and resource ARNs the "
                "principal needs.",
                idx,
            ))
        elif act_star:
            issues.append(PolicyIssue(
                "POL-002", "medium", "All actions allowed (Action \"*\")",
                "Every action is allowed on the listed resources, including destructive and "
                "permission-changing ones (e.g. s3:PutBucketPolicy, kms:ScheduleKeyDeletion). "
                "List the actions actually needed.",
                idx,
            ))
        else:
            service_wild = [a for a in actions if re.fullmatch(r"[\w-]+:\*", a)]
            if service_wild:
                sensitive = [a for a in service_wild if a.split(":")[0].lower() in
                             ("iam", "sts", "kms", "secretsmanager", "organizations", "lambda", "ec2", "s3")]
                issues.append(PolicyIssue(
                    "POL-002", "high" if sensitive and res_star else "medium",
                    f"Service-wide wildcard action: {', '.join(service_wild)}",
                    "A service:* action grants every current and future action in that service, "
                    "including permission-management and delete operations. List only the "
                    "specific actions required.",
                    idx,
                ))

        if not act_star:
            privesc = sorted({p for p in PRIVESC_ACTIONS for a in actions if _action_matches(a, p)})
            if privesc:
                scoped = not res_star
                issues.append(PolicyIssue(
                    "POL-004", "medium" if scoped else "high",
                    f"Privilege-escalation capable action(s): {', '.join(privesc[:6])}{'...' if len(privesc) > 6 else ''}",
                    "These actions let the principal grant itself or a role it controls more "
                    "permissions (new policy version, attach/put policy, PassRole into a more "
                    "privileged service, push code into a Lambda that runs as another role). "
                    + ("Resources are scoped -- verify none of them is a more privileged role/policy."
                       if scoped else "Granted on Resource \"*\"; restrict to specific ARNs, and add "
                       "iam:PassedToService conditions for PassRole."),
                    idx,
                    confidence="REVIEW" if scoped else None,
                ))

        if res_star and not act_star:
            sensitive_reads = sorted({r for r in SENSITIVE_READ_ACTIONS for a in actions if _action_matches(a, r)})
            if sensitive_reads:
                issues.append(PolicyIssue(
                    "POL-006", "medium", f"Data/key-material read on Resource \"*\": {', '.join(sensitive_reads[:5])}",
                    "Reading objects, secrets, parameters or decrypting with any KMS key across "
                    "the whole account is rarely needed. Scope Resource to the specific "
                    "bucket/secret/key ARNs.",
                    idx,
                ))
            writes = [a for a in actions if not a.split(":")[-1].lower().startswith(_READ_ONLY_PREFIXES)]
            if writes and not any(i.id in ("POL-002", "POL-004") and i.statement_index == idx for i in issues):
                issues.append(PolicyIssue(
                    "POL-003", "medium", "Write/modify actions on Resource \"*\"",
                    f"Non-read actions ({', '.join(writes[:5])}) are allowed on every resource. "
                    "Scope Resource to the specific ARNs (some actions, like ec2:Describe*, "
                    "genuinely require \"*\" -- writes almost never do).",
                    idx,
                ))

        # ── resource-policy / trust-policy principals ─────────────────────
        principals = _principals(s)
        if any(_is_wild_principal(p) for p in principals):
            protective = [k for k in conds if k in (
                "aws:sourcearn", "aws:sourceaccount", "aws:principalorgid", "aws:principalaccount",
                "aws:sourcevpce", "aws:sourcevpc", "aws:principalarn", "aws:sourceip", "aws:sourceorgid",
                "kms:calleraccount", "kms:viaservice")]
            if not conds:
                issues.append(PolicyIssue(
                    "POL-005", "high", "Public principal (\"*\") with no Condition",
                    "Anyone -- including anonymous users and every AWS account -- is granted "
                    f"{', '.join(actions[:4]) or 'these actions'}. Restrict Principal to specific "
                    "accounts/roles, or add aws:PrincipalOrgID / aws:SourceArn conditions.",
                    idx,
                ))
            elif not protective:
                issues.append(PolicyIssue(
                    "POL-005", "medium", "Public principal (\"*\") restricted only by non-identity conditions",
                    f"Conditions present ({', '.join(conds)}) don't restrict *who* the caller is "
                    "(no aws:PrincipalOrgID/aws:SourceArn/aws:SourceAccount/aws:SourceVpce). "
                    "Verify these conditions actually prevent arbitrary-account access.",
                    idx, confidence="REVIEW",
                ))

        ptypes = _principal_types(s)
        federated = ptypes.get("Federated", [])
        assume_web = any(_action_matches(a, "sts:AssumeRoleWithWebIdentity") for a in actions)
        if federated and assume_web:
            oidc = [f for f in federated if _OIDC_HOSTS.search(f) or "oidc-provider" in f]
            if oidc:
                sub_keys = [k for k in conds if k.endswith(":sub")]
                aud_keys = [k for k in conds if k.endswith(":aud")]
                if not sub_keys:
                    issues.append(PolicyIssue(
                        "POL-009", "high", "OIDC trust policy has no `sub` condition",
                        "Any identity the OIDC provider issues a token for -- e.g. any GitLab "
                        "project/branch, or any GitHub repository -- can assume this role. Pin "
                        "the `sub` claim to the exact project path and ref (e.g. "
                        "project_path:group/project:ref_type:branch:ref:main).",
                        idx,
                    ))
                else:
                    wild = [v for k in sub_keys for v in conds[k] if "*" in v]
                    if wild:
                        issues.append(PolicyIssue(
                            "POL-009", "medium", f"OIDC trust `sub` condition uses a wildcard: {wild[0]}",
                            "A wildcarded `sub` (e.g. any branch, or any project in a group) "
                            "lets unprotected branches / other projects assume the role. "
                            "Restrict to protected refs of the specific project.",
                            idx, confidence="REVIEW",
                        ))
                if not aud_keys:
                    issues.append(PolicyIssue(
                        "POL-009", "low", "OIDC trust policy has no `aud` condition",
                        "Pin the audience claim (e.g. `gitlab.com:aud` / `sts.amazonaws.com`) "
                        "so tokens minted for another audience can't be replayed here.",
                        idx,
                    ))

        aws_principals = ptypes.get("AWS", [])
        assume = any(_action_matches(a, "sts:AssumeRole") for a in actions)
        foreign = [p for p in aws_principals if re.search(r"\d{12}", p)]
        if assume and foreign and "sts:externalid" not in conds:
            issues.append(PolicyIssue(
                "POL-010", "low", "Cross-account AssumeRole trust without sts:ExternalId",
                f"Principal(s) {', '.join(foreign[:3])} can assume this role. If any is a "
                "third party, require an sts:ExternalId condition (confused-deputy protection); "
                "trusting a whole account via :root delegates the decision to that account's admins.",
                idx, confidence="REVIEW",
            ))

    if is_bucket_policy:
        enforces_tls = any(
            str(s.get("Effect", "")).lower() == "deny" and "aws:securetransport" in _condition_keys(s)
            for s in sts
        )
        if not enforces_tls:
            issues.append(PolicyIssue(
                "POL-008", "low", "S3 bucket policy does not deny non-TLS requests",
                "Add a Deny statement on s3:* for Principal \"*\" with Condition "
                "{\"Bool\": {\"aws:SecureTransport\": \"false\"}} so the bucket can't be read "
                "or written over plain HTTP.",
                -1,
            ))
    return issues


# ── standalone policy files ────────────────────────────────────────────────

POLICY_FILE_SUFFIXES = (".json", ".json.tpl", ".json.tftpl", ".tpl", ".tftpl", ".policy")


def _iter_policy_candidates(root):
    from core.fsutil import _SKIP_DIRS

    for path in root.rglob("*"):
        if not path.is_file() or any(p in _SKIP_DIRS or p == ".terraform" for p in path.parts):
            continue
        name = path.name.lower()
        if name in ("package.json", "package-lock.json", "tsconfig.json", "composer.json", "composer.lock") \
                or name.endswith((".tfstate", ".tfstate.backup", ".tfvars.json")):
            continue
        if name.endswith(POLICY_FILE_SUFFIXES) and path.stat().st_size < 5_000_000:
            yield path


def _parse_jsonish(text: str):
    import json

    try:
        return json.loads(text)
    except ValueError:
        pass
    # Terraform templatefile() / envsubst placeholders.
    cleaned = re.sub(r'(?<!")\$\{[^}]*\}(?!")', '"${ref}"', text)
    cleaned = re.sub(r"%\{[^}]*\}", "", cleaned)
    try:
        return json.loads(cleaned)
    except ValueError:
        return None


def _find_policies(node, out: list):
    if isinstance(node, dict):
        if looks_like_policy(node):
            out.append(node)
            return
        for v in node.values():
            _find_policies(v, out)
    elif isinstance(node, list):
        for v in node:
            _find_policies(v, out)


def scan_policy_files(root):
    """Findings for every IAM-shaped document in a .json / .json.tpl file
    (identity policies, bucket/key/queue policies, trust policies, policies
    nested inside CloudFormation or other JSON)."""
    from core.fsutil import read_text_safe
    from core.rulescan import make_finding, rel

    findings = []
    for path in _iter_policy_candidates(root):
        text = read_text_safe(path)
        if '"Statement"' not in text and "'Statement'" not in text:
            continue
        data = _parse_jsonish(text)
        if data is None:
            continue
        policies: list = []
        _find_policies(data, policies)
        if not policies:
            continue
        effect_lines = [text.count("\n", 0, m.start()) + 1 for m in re.finditer(r'"Effect"\s*:', text)]
        statement_lines = [text.count("\n", 0, m.start()) + 1 for m in re.finditer(r'"Statement"\s*:', text)]
        offset = 0
        for p_idx, doc in enumerate(policies):
            doc_line = statement_lines[p_idx] if p_idx < len(statement_lines) else 1
            n = len(statements(doc))
            for issue in check_policy(doc):
                if issue.statement_index >= 0 and offset + issue.statement_index < len(effect_lines):
                    line = effect_lines[offset + issue.statement_index]
                else:
                    line = doc_line
                sid = ""
                if issue.statement_index >= 0:
                    sid_val = statements(doc)[issue.statement_index].get("Sid")
                    sid = f" [Sid {sid_val}]" if sid_val else ""
                findings.append(make_finding(issue.id, issue.severity, issue.title + sid, issue.note,
                                             rel(path, root), line, issue.confidence))
            offset += n
    return findings


def has_policy_files(root) -> bool:
    from core.fsutil import read_text_safe

    for path in _iter_policy_candidates(root):
        text = read_text_safe(path)
        if '"Statement"' in text and '"Effect"' in text:
            return True
    return False
