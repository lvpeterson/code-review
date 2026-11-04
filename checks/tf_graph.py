"""Whole-project Terraform model shared by the Terraform, IAM-policy, GitLab CI
and Lambda analyzers.

`load(root)` parses every .tf/.hcl file once (cached per root), runs the
variable resolver (checks/tf_resolve.py), and then links things the
per-resource rules can't see on their own:

  * IAM roles -> every policy that grants them permissions: inline_policy,
    managed_policy_arns, aws_iam_role_policy, *_policy_attachment (AWS
    managed or customer aws_iam_policy), with policy bodies from
    jsonencode/heredoc, data "aws_iam_policy_document", file() and
    templatefile(). Each role gets a capability summary (admin, privilege
    escalation, data reads on *, writes...) from the POL rules.
  * Policy .json/.tpl files -> the Terraform resources that load them, so a
    finding in policies/deploy.json can say which role it lands on.
  * Lambda functions -> execution role, handler source file (via handler +
    archive_file source_dir/source_file), and public triggers (function
    URL with no auth, permission to "*", API Gateway).
  * GitLab OIDC trust policies -> which projects/refs may assume the role,
    so GitLab CI jobs can be matched against it.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from checks import iam_policy
from checks.hcl import Block, expr_to_py, load_policy_value, parse_hcl
from checks.tf_resolve import Resolver, resolve_project
from core.fsutil import _SKIP_DIRS, read_text_safe

TF_EXTENSIONS = (".tf", ".tfvars", ".hcl")

_ADMIN_MANAGED = {"AdministratorAccess", "PowerUserAccess", "IAMFullAccess"}
_BROAD_MANAGED = re.compile(r"FullAccess$|^SecretsManagerReadWrite$")
_CAPABILITY_IDS = ("POL-001", "POL-002", "POL-003", "POL-004", "POL-006", "POL-007")


# ── data model ─────────────────────────────────────────────────────────────

@dataclass
class PolicySource:
    doc: Optional[dict]
    desc: str                 # "inline_policy in iam.tf:40", "AWS managed ReadOnlyAccess", "policies/x.json"


@dataclass
class RoleInfo:
    block: Block
    address: str
    name: Optional[str]
    trust: Optional[dict] = None
    trust_desc: str = ""
    policies: list[PolicySource] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    privileged: bool = False
    can_write: bool = False

    def where(self, root: Path) -> str:
        return f"{_rel(self.block.file, root)}:{self.block.line}"

    def summary(self, root: Path, limit: int = 4) -> str:
        head = f"{self.address}" + (f" ({self.name})" if self.name else "") + f" [{self.where(root)}]"
        if not self.policies:
            return head + " -- no permission policies found in this Terraform"
        caps = self.capabilities[:limit] or ["scoped permissions (no broad/escalation patterns found)"]
        return head + " -- " + "; ".join(caps)


@dataclass
class GitlabTrust:
    role: RoleInfo
    subs: list[str]
    any_ref: bool        # sub lets any branch/MR ref of the project assume the role
    any_project: bool    # wildcard in the project path, or no sub at all
    refs: list[str]      # explicit refs it's pinned to (main, tags...)


@dataclass
class LambdaInfo:
    block: Block
    role: Optional[RoleInfo]
    handler: Optional[str]
    code_files: list[Path]
    public_via: list[str]


@dataclass
class TfProject:
    root: Path
    blocks: list[Block] = field(default_factory=list)
    by_type: dict = field(default_factory=lambda: defaultdict(list))
    texts: dict = field(default_factory=dict)
    tf_dirs: set = field(default_factory=set)
    resolver: Optional[Resolver] = None
    data_docs: dict = field(default_factory=dict)          # name -> (doc, statement lines)
    roles: dict = field(default_factory=dict)              # address -> RoleInfo
    policy_file_links: dict = field(default_factory=lambda: defaultdict(list))  # Path -> [desc]
    lambdas: list = field(default_factory=list)
    gitlab_trusts: list = field(default_factory=list)

    def role_by_name(self, name: str) -> Optional[RoleInfo]:
        for r in self.roles.values():
            if r.name == name or r.address.split(".", 1)[1] == name:
                return r
        return None


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# ── loading ────────────────────────────────────────────────────────────────

_CACHE: dict[Path, TfProject] = {}


def iter_tf_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or any(p in _SKIP_DIRS or p == ".terraform" for p in path.parts):
            continue
        if path.suffix in TF_EXTENSIONS or path.name.endswith(".tfvars.json"):
            yield path


def load(root: Path) -> TfProject:
    """Parsed + resolved + linked project, cached until a Terraform file changes."""
    files = sorted(iter_tf_files(root))
    sig = tuple((str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in files)
    key = root.resolve()
    cached = _CACHE.get(key)
    if cached is not None and getattr(cached, "_sig", None) == sig:
        return cached
    proj = TfProject(root)
    proj._sig = sig
    tfvars: dict[Path, str] = {}
    for path in files:
        text = read_text_safe(path)
        proj.texts[path] = text
        if path.suffix == ".tf":
            proj.tf_dirs.add(path.parent)
        if path.suffix in (".tf", ".hcl"):
            for b in parse_hcl(text, path):
                proj.blocks.append(b)
                if b.kind in ("resource", "data") and b.labels:
                    k = b.labels[0] if b.kind == "resource" else f"data.{b.labels[0]}"
                    proj.by_type[k].append(b)
                else:
                    proj.by_type[b.kind].append(b)
        elif path.suffix == ".tfvars" or path.name.endswith(".tfvars.json"):
            tfvars[path] = text
    proj.resolver = resolve_project(root, proj.blocks, tfvars, proj.tf_dirs)
    _build(proj)
    _CACHE[key] = proj
    return proj


def clear_cache() -> None:
    _CACHE.clear()


# ── policy documents ───────────────────────────────────────────────────────

def _lit(b: Optional[Block], name: str) -> Optional[str]:
    if b is None:
        return None
    a = b.attr(name)
    return a.literal() if a else None


def _list_literals(a) -> list[str]:
    return re.findall(r'"([^"]*)"', a.value) if a else []


def policy_doc_from_data(b: Block) -> tuple[Optional[dict], list[int]]:
    """data "aws_iam_policy_document" -> IAM JSON shape (+ statement lines)."""
    sts, lines = [], []
    for s in b.blocks("statement"):
        stmt: dict = {"Effect": (_lit(s, "effect") or "Allow").capitalize()}
        sid = _lit(s, "sid")
        if sid:
            stmt["Sid"] = sid
        for tf_name, key in (("actions", "Action"), ("not_actions", "NotAction"),
                             ("resources", "Resource"), ("not_resources", "NotResource")):
            if s.attr(tf_name):
                v = expr_to_py(s.attr(tf_name).value)
                stmt[key] = v if isinstance(v, list) else _list_literals(s.attr(tf_name)) or ["${ref}"]
        principals: dict[str, list] = {}
        for p in s.blocks("principals"):
            ptype = _lit(p, "type") or "AWS"
            ids = expr_to_py(p.attr("identifiers").value) if p.attr("identifiers") else []
            if not isinstance(ids, list):
                ids = _list_literals(p.attr("identifiers")) or ["${" + (p.attr("identifiers").value if p.attr("identifiers") else "ref") + "}"]
            principals.setdefault(ptype if ptype != "*" else "AWS", []).extend(ids)
        if principals:
            stmt["Principal"] = principals
        cond: dict[str, dict] = {}
        for c in s.blocks("condition"):
            test = _lit(c, "test") or "StringEquals"
            var = _lit(c, "variable") or "unknown"
            vals = expr_to_py(c.attr("values").value) if c.attr("values") else []
            cond.setdefault(test, {})[var] = vals if isinstance(vals, list) else _list_literals(c.attr("values")) or ["${ref}"]
        if cond:
            stmt["Condition"] = cond
        sts.append(stmt)
        lines.append(s.line)
    if not sts:
        return None, []
    return {"Version": _lit(b, "version") or "2012-10-17", "Statement": sts}, lines


_FILE_CALL = re.compile(r'^\s*(file|templatefile)\s*\(\s*"([^"]+)"')


def _file_path(expr: str, d: Path) -> Optional[Path]:
    m = _FILE_CALL.match(expr)
    if not m:
        return None
    p = m.group(2)
    p = re.sub(r"\$\{\s*path\.(?:module|root|cwd)\s*\}", ".", p)
    if "${" in p:
        return None
    return (d / p).resolve()


def policy_doc(proj: TfProject, value: str, d: Path, depth: int = 0, link_desc: Optional[str] = None) -> tuple[Optional[dict], str]:
    """Best-effort IAM document for a Terraform policy expression, plus a
    short description of where it came from."""
    if depth > 4 or not value:
        return None, ""
    v = value.strip()
    doc = load_policy_value(v)
    if doc is not None:
        return doc, "inline"
    m = re.search(r"data\.aws_iam_policy_document\.([\w-]+)\.(?:json|minified_json)", v)
    if m and m.group(1) in proj.data_docs:
        return proj.data_docs[m.group(1)][0], f"data.aws_iam_policy_document.{m.group(1)}"
    fp = _file_path(v, d)
    if fp is not None and fp.is_file():
        if link_desc:
            proj.policy_file_links[fp].append(link_desc)
        data = iam_policy._parse_jsonish(read_text_safe(fp))
        if isinstance(data, dict) and iam_policy.looks_like_policy(data):
            return data, _rel(fp, proj.root)
        return None, _rel(fp, proj.root)
    m = re.search(r"\baws_iam_policy\.([\w-]+)\.(?:arn|id|policy|name)", v)
    if m:
        for b in proj.by_type.get("aws_iam_policy", []):
            if len(b.labels) > 1 and b.labels[1] == m.group(1) and b.attr("policy"):
                doc, src = policy_doc(proj, b.attr("policy").value, b.file.parent.resolve(), depth + 1,
                                      link_desc)
                return doc, f"aws_iam_policy.{m.group(1)}" + (f" ({src})" if src and src != "inline" else "")
    return None, ""


# ── roles ──────────────────────────────────────────────────────────────────

def _refers_to(value: str, role: RoleInfo) -> bool:
    label = role.address.split(".", 1)[1]
    if re.search(rf"\baws_iam_role\.{re.escape(label)}\.(?:name|id|arn|unique_id)\b", value):
        return True
    return bool(role.name) and value.strip().strip('"') == role.name


def _capabilities(role: RoleInfo) -> None:
    caps: list[str] = []
    for src in role.policies:
        if src.doc is None:
            m = re.search(r"AWS managed (\S+)", src.desc)
            if m:
                name = m.group(1)
                if name in _ADMIN_MANAGED:
                    role.privileged = True
                    role.can_write = True
                    caps.append(f"{name} (AWS managed)")
                elif _BROAD_MANAGED.search(name):
                    role.can_write = True
                    caps.append(f"{name} (AWS managed)")
            continue
        for issue in iam_policy.check_policy(src.doc):
            if issue.id not in _CAPABILITY_IDS:
                continue
            if issue.id == "POL-001" or (issue.id in ("POL-004", "POL-002") and issue.severity == "high"):
                role.privileged = True
            if issue.id in ("POL-001", "POL-002", "POL-003", "POL-004", "POL-007"):
                role.can_write = True
            caps.append(issue.title)
        for s in iam_policy.statements(src.doc):
            if str(s.get("Effect", "")).lower() != "allow":
                continue
            for a in iam_policy.as_list(s.get("Action")):
                verb = str(a).split(":", 1)[-1].lower()
                if not verb.startswith(iam_policy._READ_ONLY_PREFIXES) or verb.startswith("*"):
                    role.can_write = True
    role.capabilities = list(dict.fromkeys(caps))


def _build_roles(proj: TfProject) -> None:
    root = proj.root
    for b in proj.by_type.get("aws_iam_role", []):
        if len(b.labels) < 2:
            continue
        r = RoleInfo(b, f"aws_iam_role.{b.labels[1]}", _lit(b, "name"))
        d = b.file.parent.resolve()
        if b.attr("assume_role_policy"):
            r.trust, r.trust_desc = policy_doc(proj, b.attr("assume_role_policy").value, d,
                                               link_desc=f"trust policy of {r.address} ({_rel(b.file, root)}:{b.line})")
        for ip in b.blocks("inline_policy"):
            if ip.attr("policy"):
                doc, src = policy_doc(proj, ip.attr("policy").value, d,
                                      link_desc=f"inline_policy of {r.address} ({_rel(b.file, root)}:{ip.line})")
                r.policies.append(PolicySource(doc, f"inline_policy ({src or 'unparsed'})"))
        for arn in _list_literals(b.attr("managed_policy_arns")):
            r.policies.append(_managed(proj, arn, d, r))
        proj.roles[r.address] = r

    for rtype in ("aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_iam_policy_attachment"):
        for b in proj.by_type.get(rtype, []):
            d = b.file.parent.resolve()
            role_attr = b.attr("role") or b.attr("roles")
            if not role_attr:
                continue
            for r in proj.roles.values():
                if not (_refers_to(role_attr.value, r) or any(_refers_to(x, r) for x in re.findall(r"[\w.\-\"]+", role_attr.value))):
                    continue
                where = f"{rtype}.{b.labels[1] if len(b.labels) > 1 else ''} ({_rel(b.file, root)}:{b.line})"
                if rtype == "aws_iam_role_policy" and b.attr("policy"):
                    doc, src = policy_doc(proj, b.attr("policy").value, d, link_desc=f"{where} on {r.address}")
                    r.policies.append(PolicySource(doc, f"{where} ({src or 'unparsed'})"))
                elif b.attr("policy_arn"):
                    r.policies.append(_managed(proj, b.attr("policy_arn").value, d, r, where))
    for r in proj.roles.values():
        _capabilities(r)


def _managed(proj: TfProject, arn_expr: str, d: Path, role: RoleInfo, where: str = "") -> PolicySource:
    m = re.search(r"arn:aws[\w-]*:iam::aws:policy/(?:[\w-]+/)*([\w-]+)", arn_expr)
    if m:
        return PolicySource(None, f"AWS managed {m.group(1)}")
    doc, src = policy_doc(proj, arn_expr, d, link_desc=f"{where or 'attachment'} on {role.address}")
    return PolicySource(doc, f"{where} ({src or 'customer policy not found'})")


# ── GitLab trust ───────────────────────────────────────────────────────────

_SUB = re.compile(r"project_path:(?P<project>[^:]+)(?::ref_type:(?P<rtype>[^:]+))?(?::ref:(?P<ref>.+))?")


def classify_gitlab_subs(subs: list[str]) -> tuple[bool, bool, list[str]]:
    """(any_ref, any_project, pinned refs) for GitLab `sub` claim patterns."""
    if not subs:
        return True, True, []
    any_ref = any_project = False
    refs: list[str] = []
    for s in subs:
        m = _SUB.match(s)
        if not m:
            any_ref = any_ref or "*" in s
            any_project = any_project or s.strip() in ("*", "project_path:*")
            continue
        if "*" in m.group("project"):
            any_project = True
        ref = m.group("ref")
        rtype = m.group("rtype")
        if ref is None or "*" in (ref or "") or (rtype and "*" in rtype):
            any_ref = True
        else:
            refs.append(f"{rtype or 'ref'}:{ref}")
    return any_ref, any_project, refs


def _gitlab_federated(principals: list[str]) -> bool:
    return any(re.search(r"(?i)gitlab", p) for p in principals)


def _build_gitlab_trusts(proj: TfProject) -> None:
    for r in proj.roles.values():
        if not r.trust:
            continue
        for s in iam_policy.statements(r.trust):
            if str(s.get("Effect", "")).lower() != "allow":
                continue
            fed = iam_policy._principal_types(s).get("Federated", [])
            if not fed or not _gitlab_federated([str(f) for f in fed]):
                continue
            conds = iam_policy._condition_keys(s)
            subs = [str(v) for k, vals in conds.items() if k.endswith(":sub") for v in vals]
            any_ref, any_project, refs = classify_gitlab_subs(subs)
            proj.gitlab_trusts.append(GitlabTrust(r, subs, any_ref, any_project, refs))


# ── Lambda ─────────────────────────────────────────────────────────────────

def _expand_path(expr: Optional[str], d: Path) -> Optional[Path]:
    if not expr:
        return None
    s = expr.strip().strip('"')
    s = re.sub(r"\$\{\s*path\.(?:module|root|cwd)\s*\}", ".", s)
    if "${" in s or not s:
        return None
    return (d / s).resolve()


def _build_lambdas(proj: TfProject) -> None:
    py_files = None
    for b in proj.by_type.get("aws_lambda_function", []):
        if len(b.labels) < 2:
            continue
        label = b.labels[1]
        role = None
        if b.attr("role"):
            m = re.search(r"\baws_iam_role\.([\w-]+)\.", b.attr("role").value)
            if m:
                role = proj.roles.get(f"aws_iam_role.{m.group(1)}")
        handler = _lit(b, "handler")
        code: list[Path] = []
        src_dir = src_file = None
        fn = b.attr("filename").value if b.attr("filename") else ""
        am = re.search(r"data\.archive_file\.([\w-]+)\.output_path", fn)
        if am:
            for ab in proj.by_type.get("data.archive_file", []):
                if len(ab.labels) > 1 and ab.labels[1] == am.group(1):
                    ad = ab.file.parent.resolve()
                    src_dir = _expand_path(ab.attr("source_dir").value if ab.attr("source_dir") else None, ad)
                    src_file = _expand_path(ab.attr("source_file").value if ab.attr("source_file") else None, ad)
        if handler and "." in handler:
            mod_path = handler.rsplit(".", 1)[0].replace(".", "/") + ".py"
            if src_file and src_file.suffix == ".py":
                code = [src_file]
            elif src_dir and (src_dir / mod_path).is_file():
                code = [(src_dir / mod_path).resolve()]
            else:
                if py_files is None:
                    py_files = [p.resolve() for p in proj.root.rglob("*.py")
                                if not any(x in _SKIP_DIRS for x in p.parts)]
                matches = [p for p in py_files if p.as_posix().endswith("/" + mod_path)]
                if src_dir:
                    matches = [p for p in matches if str(p).startswith(str(src_dir))] or matches
                code = matches[:3]
        public: list[str] = []
        ref = re.compile(rf"\baws_lambda_function\.{re.escape(label)}\.")
        for u in proj.by_type.get("aws_lambda_function_url", []):
            if u.attr("function_name") and ref.search(u.attr("function_name").value) and _lit(u, "authorization_type") == "NONE":
                public.append(f"function URL with no auth ({_rel(u.file, proj.root)}:{u.line})")
        for p in proj.by_type.get("aws_lambda_permission", []):
            if p.attr("function_name") and ref.search(p.attr("function_name").value):
                principal = _lit(p, "principal") or ""
                if principal == "*" or principal.startswith("apigateway"):
                    public.append(f"invoke permission for {principal} ({_rel(p.file, proj.root)}:{p.line})")
        proj.lambdas.append(LambdaInfo(b, role, handler, code, public))


def _build(proj: TfProject) -> None:
    for b in proj.by_type.get("data.aws_iam_policy_document", []):
        if len(b.labels) > 1:
            proj.data_docs[b.labels[1]] = policy_doc_from_data(b)
    _build_roles(proj)
    _build_gitlab_trusts(proj)
    _build_lambdas(proj)
    # Policy files loaded by aws_iam_policy / bucket policies etc. that no role uses.
    for rtype in ("aws_iam_policy", "aws_s3_bucket_policy", "aws_kms_key", "aws_sqs_queue_policy",
                  "aws_sns_topic_policy", "aws_ecr_repository_policy", "aws_secretsmanager_secret_policy"):
        for b in proj.by_type.get(rtype, []):
            a = b.attr("policy")
            if a:
                fp = _file_path(a.value, b.file.parent.resolve())
                if fp is not None:
                    desc = f"{rtype}.{b.labels[1] if len(b.labels) > 1 else ''} ({_rel(b.file, proj.root)}:{b.line})"
                    if desc not in proj.policy_file_links[fp]:
                        proj.policy_file_links[fp].append(desc)
