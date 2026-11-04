"""Terraform (AWS-focused) misconfiguration checks -- TF-<AREA>-NNN.

Runs over every .tf / .tfvars / .hcl file. Three layers:

  1. Per-resource attribute checks (public S3 ACLs, 0.0.0.0/0 ingress on
     admin ports, IMDSv1, unencrypted RDS, public Lambda URLs, ...).
  2. Cross-resource checks that need the whole project (an aws_s3_bucket
     with no aws_s3_bucket_public_access_block pointing at it, a root module
     with no .terraform.lock.hcl, committed state files).
  3. Every policy document Terraform defines -- jsonencode({...}), heredoc
     JSON, and data "aws_iam_policy_document" -- is converted to IAM JSON
     shape and run through checks/iam_policy.py (POL-xxx).

Before any rule runs, checks/tf_resolve.py substitutes var./local./module
input references with the values they resolve to (tfvars > calling module >
default), so `acl = var.bucket_acl` with a "public-read" default is caught;
the finding text says where the value came from. checks/tf_graph.py adds
the cross-resource model (role permissions, GitLab OIDC trust, Lambda ->
role) used by the TF-OIDC rules here and by the Lambda / GitLab analyzers.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

from checks import iam_policy, secrets, tf_graph
from checks.hcl import Attr, Block, load_policy_value
from checks.tf_graph import iter_tf_files  # noqa: F401  (re-exported for callers)
from core.models import Finding
from core.rulescan import LineRule, make_finding, rel, scan_text

TF_EXTENSIONS = (".tf", ".tfvars", ".hcl")

_SECRETISH_NAME = re.compile(
    r"(?i)(password|passwd|secret|token|private_key|api_key|apikey|access_key|credential|client_secret|passphrase)"
)
_ADMIN_PORTS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    2375: "Docker API", 2376: "Docker API", 2379: "etcd", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis",
    9200: "Elasticsearch", 9300: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 9092: "Kafka",
}
_DEPRECATED_RUNTIMES = re.compile(
    r"^(python2\.7|python3\.[0-8]|nodejs(?:4\.3|6\.10|8\.10|10\.x|12\.x|14\.x|16\.x)?|java8|"
    r"dotnetcore\d\.\d|dotnet[56]|ruby2\.\d|go1\.x|provided)$"
)
_OLD_ELB_TLS = re.compile(r"ELBSecurityPolicy-(?:2015-05|2016-08|TLS-1-0|TLS-1-1|TLS13-1-1|TLS13-1-0)|"
                          r"ELBSecurityPolicy-FS-(?:2018-06|1-1)")
_PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}

# Resource types whose `policy` (or other named attribute) is an IAM-shaped document.
_POLICY_ATTRS = {
    "aws_iam_policy": "policy", "aws_iam_role_policy": "policy", "aws_iam_user_policy": "policy",
    "aws_iam_group_policy": "policy", "aws_iam_role": "assume_role_policy",
    "aws_s3_bucket_policy": "policy", "aws_kms_key": "policy", "aws_sqs_queue_policy": "policy",
    "aws_sns_topic_policy": "policy", "aws_ecr_repository_policy": "policy",
    "aws_secretsmanager_secret_policy": "policy", "aws_s3_bucket": "policy",
    "aws_sqs_queue": "policy", "aws_sns_topic": "policy", "aws_kms_key_policy": "policy",
    "aws_iam_role_policy_attachment": None,
}


class _Ctx:
    def __init__(self, root: Path):
        self.root = root
        self.findings: list[Finding] = []
        self.blocks: list[Block] = []
        self.by_type: dict[str, list[Block]] = defaultdict(list)
        self.dirs_with_tf: set[Path] = set()

    def add(self, block: Block, check_id: str, severity: str, title: str, note: str,
            line: Optional[int] = None, confidence: Optional[str] = None) -> None:
        name = ".".join(block.labels)
        note += _resolution_note(block, line or block.line, title + " " + note)
        self.findings.append(make_finding(
            check_id, severity, f"{title} [{name}]" if name else title, note,
            rel(block.file, self.root), line or block.line, confidence,
        ))

    def references(self, rtype: str, target: Block, attr: str = "bucket") -> list[Block]:
        """Resources of `rtype` whose `attr` points at `target` (by reference
        or by matching literal name)."""
        ref = f"{target.labels[0]}.{target.labels[1]}." if len(target.labels) >= 2 else None
        target_literal = target.attr("bucket").literal() if target.attr("bucket") else None
        out = []
        for b in self.by_type.get(rtype, []):
            a = b.attr(attr)
            if not a:
                continue
            if ref and ref in a.value:
                out.append(b)
            elif target_literal and a.literal() == target_literal:
                out.append(b)
        return out


def _resolution_note(block: Block, line: int, text: str) -> str:
    """' Value resolved: acl = var.bucket_acl -> "public-read" (terraform.tfvars:3).'
    for resolved attributes on the finding's line or named in its text."""
    named, on_line = [], []
    for b in block.walk():
        nested_here = b is not block and b.line == line   # finding points at a nested block (ingress {...})
        for a in b.attrs.values():
            if a.raw is None:
                continue
            note = f"`{a.name} = {' '.join(a.raw.split())[:50]}` resolves via {a.via}"
            if re.search(rf"\b{re.escape(a.name)}\b", text):
                named.append(note)
            elif a.line == line or nested_here:
                on_line.append(note)
    hits = named or on_line
    return (" Value resolved: " + " | ".join(hits[:2]) + ".") if hits else ""


def scan_project(root: Path) -> list[Finding]:
    proj = tf_graph.load(root)
    ctx = _Ctx(root)
    ctx.proj = proj
    texts = proj.texts
    ctx.dirs_with_tf = set(proj.tf_dirs)
    ctx.blocks = proj.blocks
    ctx.by_type = proj.by_type

    for b in ctx.blocks:
        if b.kind == "resource" and b.labels:
            check = _RESOURCE_CHECKS.get(b.labels[0])
            if check:
                check(ctx, b)
            _check_resource_policies(ctx, b)
            _check_provisioners(ctx, b)
        elif b.kind == "data" and b.labels:
            if b.labels[0] == "aws_iam_policy_document":
                _check_policy_document_data(ctx, b)
            elif b.labels[0] == "external":
                ctx.add(b, "TF-EXEC-002", "medium", "data \"external\" runs a local program at plan time",
                        "External data sources execute during `terraform plan`, not just apply. If plan "
                        "runs in merge-request pipelines, anyone who can push a branch can change the "
                        "program (or its inputs) and run code on the runner with the pipeline's cloud "
                        "credentials. Confirm plan jobs with credentials only run on protected refs.",
                        confidence="REVIEW")
        elif b.kind == "provider":
            _check_provider(ctx, b)
        elif b.kind == "terraform":
            _check_terraform_block(ctx, b)
        elif b.kind == "module":
            _check_module(ctx, b)
        elif b.kind == "variable":
            _check_variable(ctx, b)
        elif b.kind == "output":
            _check_output(ctx, b)

    _project_checks(ctx)

    line_rules = secrets.secret_rules() + _TF_LINE_RULES
    for path, text in texts.items():
        ctx.findings.extend(scan_text(text, line_rules, rel(path, root), "hcl"))
    return ctx.findings


# ── helpers ────────────────────────────────────────────────────────────────

def _lit(b: Block, name: str) -> Optional[str]:
    a = b.attr(name)
    return a.literal() if a else None


def _bool(b: Optional[Block], name: str) -> Optional[bool]:
    if b is None:
        return None
    a = b.attr(name)
    return a.as_bool() if a else None


def _line(b: Block, name: str) -> int:
    a = b.attr(name)
    return a.line if a else b.line


def _list_literals(a: Optional[Attr]) -> list[str]:
    if not a:
        return []
    return re.findall(r'"([^"]*)"', a.value)


def _ports(from_port: Optional[float], to_port: Optional[float], protocol: str) -> tuple[bool, list[str]]:
    """(all_ports, [admin services exposed])"""
    if protocol in ("-1", "all"):
        return True, []
    if from_port is None or to_port is None:
        return False, []
    lo, hi = int(from_port), int(to_port)
    if lo <= 0 and hi >= 65535:
        return True, []
    exposed = [f"{p}/{name}" for p, name in _ADMIN_PORTS.items() if lo <= p <= hi]
    return False, exposed


def _public_cidr(values: list[str]) -> bool:
    return any(v in ("0.0.0.0/0", "::/0") for v in values)


def _report_ingress(ctx: _Ctx, owner: Block, line: int, cidrs: list[str], from_p, to_p, proto: str) -> None:
    if not _public_cidr(cidrs):
        return
    all_ports, exposed = _ports(from_p, to_p, proto)
    if all_ports:
        ctx.add(owner, "TF-NET-001", "high", "Security group allows all ports/protocols from the internet",
                "Ingress from 0.0.0.0/0 (or ::/0) on every port. Restrict the source CIDR and the port "
                "range to what the workload actually serves.", line)
    elif exposed:
        ctx.add(owner, "TF-NET-001", "high", f"Admin/database port open to the internet: {', '.join(exposed)}",
                "Management and datastore ports reachable from anywhere are a primary initial-access "
                "vector. Use SSM Session Manager / a bastion / VPN, and allow only known source CIDRs "
                "or security groups.", line)
    else:
        lo = int(from_p) if from_p is not None else None
        if lo not in (80, 443):
            ctx.add(owner, "TF-NET-002", "medium", f"Port {lo}-{int(to_p) if to_p is not None else '?'} open to the internet",
                    "Ingress from 0.0.0.0/0 on a non-web port. Confirm this service is meant to be public.",
                    line, confidence="REVIEW")


# ── resource checks ────────────────────────────────────────────────────────

def _s3_bucket(ctx: _Ctx, b: Block) -> None:
    acl = _lit(b, "acl")
    if acl in _PUBLIC_ACLS:
        ctx.add(b, "TF-S3-001", "high", f"S3 bucket ACL is {acl}",
                "The canned ACL grants read (or write) to everyone / every AWS user. Remove it, set "
                "object ownership to BucketOwnerEnforced, and serve public content through CloudFront "
                "with origin access control instead.", _line(b, "acl"))

    has_account_block = bool(ctx.by_type.get("aws_s3_account_public_access_block"))
    if not ctx.references("aws_s3_bucket_public_access_block", b) and not has_account_block:
        ctx.add(b, "TF-S3-002", "medium", "S3 bucket has no public access block",
                "No aws_s3_bucket_public_access_block (or account-level block) covers this bucket, so "
                "a later ACL or bucket-policy change can make it public. Add one with all four "
                "settings set to true.")

    if not b.block("server_side_encryption_configuration") and not ctx.references(
            "aws_s3_bucket_server_side_encryption_configuration", b):
        ctx.add(b, "TF-S3-003", "low", "S3 bucket has no explicit encryption configuration",
                "AWS applies SSE-S3 by default since 2023, but that gives no key-level access control "
                "or audit trail. For sensitive data configure SSE-KMS with a customer-managed key "
                "(and bucket_key_enabled = true).")

    versioning = b.block("versioning")
    v_resources = ctx.references("aws_s3_bucket_versioning", b)
    if versioning is not None and _bool(versioning, "enabled") is False:
        ctx.add(b, "TF-S3-004", "low", "S3 versioning disabled",
                "Without versioning, an overwrite or delete (accidental or ransomware) is permanent.",
                versioning.line)
    elif versioning is None and not v_resources:
        ctx.add(b, "TF-S3-004", "low", "S3 bucket has no versioning configuration",
                "Without versioning, an overwrite or delete (accidental or ransomware) is permanent.")

    if not b.block("logging") and not ctx.references("aws_s3_bucket_logging", b):
        ctx.add(b, "TF-S3-005", "low", "S3 server access logging not configured",
                "No access logging (aws_s3_bucket_logging) for this bucket -- object-level access "
                "can't be reconstructed after an incident unless CloudTrail data events are enabled.")

    if not ctx.references("aws_s3_bucket_policy", b) and not b.attr("policy"):
        ctx.add(b, "TF-S3-006", "low", "S3 bucket has no bucket policy enforcing TLS",
                "Add a bucket policy denying requests where aws:SecureTransport is false.")


def _s3_bucket_acl(ctx: _Ctx, b: Block) -> None:
    acl = _lit(b, "acl")
    if acl in _PUBLIC_ACLS:
        ctx.add(b, "TF-S3-001", "high", f"S3 bucket ACL is {acl}",
                "The canned ACL grants read (or write) to everyone / every AWS user.", _line(b, "acl"))
    if re.search(r"AllUsers|AuthenticatedUsers", b.text):
        ctx.add(b, "TF-S3-001", "high", "S3 ACL grant to AllUsers/AuthenticatedUsers",
                "A grant to the global AllUsers/AuthenticatedUsers group makes the bucket or objects public.")


def _s3_pab(ctx: _Ctx, b: Block) -> None:
    off = [k for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
           if _bool(b, k) is not True]
    if off:
        ctx.add(b, "TF-S3-007", "medium", f"Public access block not fully enabled: {', '.join(off)}",
                "Each of these defaults to false when omitted. Set all four to true unless the bucket "
                "is intentionally public (and document why).")


def _s3_cors(ctx: _Ctx, b: Block) -> None:
    for rule in b.blocks("cors_rule"):
        if "*" in _list_literals(rule.attr("allowed_origins")):
            ctx.add(b, "TF-S3-008", "low", "S3 CORS allows any origin",
                    "allowed_origins = [\"*\"] lets any website read responses cross-origin. Restrict to "
                    "the application's own origins.", rule.line)


def _s3_website(ctx: _Ctx, b: Block) -> None:
    ctx.add(b, "TF-S3-009", "info", "S3 static website hosting enabled",
            "Website endpoints are HTTP-only and require the bucket to be public. Prefer CloudFront + "
            "origin access control.", confidence="REVIEW")


def _sg(ctx: _Ctx, b: Block) -> None:
    for ing in b.blocks("ingress"):
        cidrs = _list_literals(ing.attr("cidr_blocks")) + _list_literals(ing.attr("ipv6_cidr_blocks"))
        fp = ing.attr("from_port").as_number() if ing.attr("from_port") else None
        tp = ing.attr("to_port").as_number() if ing.attr("to_port") else None
        _report_ingress(ctx, b, ing.line, cidrs, fp, tp, (_lit(ing, "protocol") or "").lower())
    for dyn in b.blocks("dynamic"):
        if dyn.labels and dyn.labels[0] == "ingress" and re.search(r'"0\.0\.0\.0/0"|"::/0"', dyn.text):
            ctx.add(b, "TF-NET-002", "medium", "Dynamic ingress rule includes 0.0.0.0/0",
                    "A dynamic ingress block contains a public CIDR -- check which ports it is applied to.",
                    dyn.line, confidence="REVIEW")
    if b.labels and b.labels[0] == "aws_default_security_group" and (b.blocks("ingress") or b.blocks("egress")):
        ctx.add(b, "TF-NET-004", "low", "Default security group has rules",
                "Resources launched without an explicit SG land in the default group. Keep it empty.")


def _sg_rule(ctx: _Ctx, b: Block) -> None:
    kind = b.labels[0]
    if kind == "aws_security_group_rule" and _lit(b, "type") != "ingress":
        return
    cidrs = (_list_literals(b.attr("cidr_blocks")) + _list_literals(b.attr("ipv6_cidr_blocks"))
             + [v for v in (_lit(b, "cidr_ipv4"), _lit(b, "cidr_ipv6")) if v])
    fp = b.attr("from_port").as_number() if b.attr("from_port") else None
    tp = b.attr("to_port").as_number() if b.attr("to_port") else None
    proto = (_lit(b, "protocol") or _lit(b, "ip_protocol") or "").lower()
    _report_ingress(ctx, b, b.line, cidrs, fp, tp, proto)


def _instance(ctx: _Ctx, b: Block) -> None:
    md = b.block("metadata_options")
    tokens = _lit(md, "http_tokens") if md else None
    if tokens != "required":
        ctx.add(b, "TF-EC2-001", "medium", "IMDSv2 not enforced (http_tokens != \"required\")",
                "IMDSv1 lets any SSRF in software on the instance read the instance-role credentials "
                "from 169.254.169.254. Set metadata_options { http_tokens = \"required\" }.",
                md.line if md else None)
    if _bool(b, "associate_public_ip_address") is True:
        ctx.add(b, "TF-EC2-002", "low", "Instance gets a public IP",
                "Confirm the instance needs to be directly internet-reachable.", _line(b, "associate_public_ip_address"))
    for dev in b.blocks("root_block_device") + b.blocks("ebs_block_device"):
        if _bool(dev, "encrypted") is not True:
            ctx.add(b, "TF-ENC-001", "low", f"{dev.kind} not encrypted",
                    "Set encrypted = true (optionally with a KMS key), or enable EBS encryption by default.",
                    dev.line)


def _ebs(ctx: _Ctx, b: Block) -> None:
    if _bool(b, "encrypted") is not True:
        ctx.add(b, "TF-ENC-001", "low", "EBS volume not encrypted",
                "Set encrypted = true, or enable aws_ebs_encryption_by_default for the account/region.")


def _rds(ctx: _Ctx, b: Block) -> None:
    if _bool(b, "publicly_accessible") is True:
        ctx.add(b, "TF-DB-001", "high", "Database is publicly accessible",
                "publicly_accessible = true gives the instance a public endpoint. Keep databases in "
                "private subnets and reach them through the application tier / SSM.",
                _line(b, "publicly_accessible"))
    if b.labels[0] != "aws_rds_cluster_instance" and _bool(b, "storage_encrypted") is not True:
        ctx.add(b, "TF-DB-002", "medium", "Database storage not encrypted",
                "storage_encrypted defaults to false and can't be changed after creation without a "
                "snapshot/restore. Set storage_encrypted = true with a KMS key.")
    if b.labels[0] != "aws_rds_cluster_instance" and _bool(b, "deletion_protection") is not True:
        ctx.add(b, "TF-DB-003", "low", "Database deletion protection disabled",
                "Set deletion_protection = true for production datastores.")
    if _bool(b, "auto_minor_version_upgrade") is False:
        ctx.add(b, "TF-DB-007", "low", "Automatic minor version upgrades disabled",
                "Minor engine releases carry security fixes. Leave auto_minor_version_upgrade on, or "
                "document the patching process that replaces it.", _line(b, "auto_minor_version_upgrade"))
    user = _lit(b, "username") or _lit(b, "master_username")
    if user and user.lower() in ("admin", "root", "postgres", "sa", "administrator", "master", "dbadmin", "awsuser", "user"):
        ctx.add(b, "TF-DB-008", "low", f"Default/guessable database admin username '{user}'",
                "Well-known admin usernames halve the work of a credential-stuffing or brute-force "
                "attack. Use a non-default name (and IAM database authentication where supported).",
                _line(b, "username") if b.attr("username") else _line(b, "master_username"))
    pw = b.attr("password") or b.attr("master_password")
    if pw and pw.literal() is None and _bool(b, "manage_master_user_password") is not True:
        ctx.add(b, "TF-DB-004", "low", "Master password managed through Terraform",
                "The password value is stored in plaintext in the Terraform state. Prefer "
                "manage_master_user_password = true (RDS-managed secret in Secrets Manager).", pw.line)


def _elasticache(ctx: _Ctx, b: Block) -> None:
    for attr, label in (("at_rest_encryption_enabled", "at rest"), ("transit_encryption_enabled", "in transit")):
        if _bool(b, attr) is not True:
            ctx.add(b, "TF-DB-005", "medium", f"ElastiCache not encrypted {label}",
                    f"Set {attr} = true (and an auth_token / RBAC for Redis).")
    if not b.attr("auth_token") and not b.attr("user_group_ids"):
        ctx.add(b, "TF-DB-009", "medium", "ElastiCache Redis without authentication",
                "No auth_token or RBAC user group -- anything that can reach the endpoint can read and "
                "write every key. Set transit_encryption_enabled = true plus auth_token or user_group_ids.")
    if _bool(b, "auto_minor_version_upgrade") is False:
        ctx.add(b, "TF-DB-007", "low", "Automatic minor version upgrades disabled",
                "Minor engine releases carry security fixes.", _line(b, "auto_minor_version_upgrade"))


def _opensearch(ctx: _Ctx, b: Block) -> None:
    if _bool(b.block("encrypt_at_rest"), "enabled") is not True:
        ctx.add(b, "TF-DB-006", "medium", "OpenSearch domain not encrypted at rest", "Enable encrypt_at_rest.")
    if _bool(b.block("node_to_node_encryption"), "enabled") is not True:
        ctx.add(b, "TF-DB-006", "medium", "OpenSearch node-to-node encryption disabled", "Enable node_to_node_encryption.")
    if _bool(b.block("domain_endpoint_options"), "enforce_https") is not True:
        ctx.add(b, "TF-DB-006", "medium", "OpenSearch does not enforce HTTPS",
                "Set domain_endpoint_options { enforce_https = true, tls_security_policy = \"Policy-Min-TLS-1-2-2019-07\" }.")


def _lambda(ctx: _Ctx, b: Block) -> None:
    runtime = _lit(b, "runtime")
    if runtime and _DEPRECATED_RUNTIMES.match(runtime):
        ctx.add(b, "TF-LMB-001", "medium", f"Deprecated Lambda runtime: {runtime}",
                "This runtime no longer gets security patches from AWS (and eventually blocks "
                "create/update). Move to a supported runtime.", _line(b, "runtime"))
    env = b.block("environment")
    if env:
        vars_attr = env.attr("variables")
        secretish = [m for m in re.findall(r'(?m)^\s*"?([A-Za-z_][\w]*)"?\s*=', vars_attr.value if vars_attr else "")
                     if _SECRETISH_NAME.search(m)]
        if secretish:
            ctx.add(b, "TF-LMB-002", "medium", f"Secret-looking Lambda environment variables: {', '.join(secretish[:4])}",
                    "Environment variables are readable by anyone with lambda:GetFunctionConfiguration, "
                    "appear in the console and in Terraform state. Store the value in Secrets Manager / "
                    "SSM SecureString and fetch it at runtime (the Parameters and Secrets extension caches it).",
                    env.line)
        if not b.attr("kms_key_arn"):
            ctx.add(b, "TF-LMB-003", "low", "Lambda environment not encrypted with a customer KMS key",
                    "Without kms_key_arn the environment is encrypted with the AWS-managed key, so any "
                    "principal with GetFunctionConfiguration can read it. Use a CMK if it holds anything sensitive.",
                    env.line)
    if not b.block("tracing_config") and not b.attr("code_signing_config_arn"):
        pass  # deliberately not flagged: noise for most reviews


def _lambda_url(ctx: _Ctx, b: Block) -> None:
    if _lit(b, "authorization_type") == "NONE":
        ctx.add(b, "TF-LMB-004", "high", "Lambda function URL with authorization_type = \"NONE\"",
                "The function is invokable by anyone on the internet with no IAM auth. Confirm the "
                "handler authenticates every request itself, or switch to AWS_IAM / API Gateway with "
                "an authorizer.", _line(b, "authorization_type"), confidence="REVIEW")
    cors = b.block("cors")
    if cors and "*" in _list_literals(cors.attr("allow_origins")):
        ctx.add(b, "TF-LMB-005", "low", "Lambda function URL CORS allows any origin",
                "Restrict allow_origins to the application's own origins.", cors.line)


def _lambda_permission(ctx: _Ctx, b: Block) -> None:
    principal = _lit(b, "principal") or ""
    if principal == "*":
        ctx.add(b, "TF-LMB-006", "high", "Lambda invoke permission granted to Principal \"*\"",
                "Any AWS account (or anyone, for function URLs) can invoke this function. Restrict "
                "the principal and add source_arn / source_account.", _line(b, "principal"))
    elif principal.endswith(".amazonaws.com") and not b.attr("source_arn"):
        sev = "medium" if principal.split(".")[0] in ("s3", "sns", "events", "apigateway", "logs", "sqs") else "low"
        ctx.add(b, "TF-LMB-007", sev, f"Lambda permission for {principal} without source_arn",
                "Without source_arn (and source_account for S3), a resource in *any* AWS account "
                "using this service can trigger the function (confused deputy). Pin the specific "
                "bucket/topic/rule/API ARN.", _line(b, "principal"))


def _layer_permission(ctx: _Ctx, b: Block) -> None:
    if _lit(b, "principal") == "*":
        ctx.add(b, "TF-LMB-008", "medium", "Lambda layer shared with every AWS account",
                "principal = \"*\" makes the layer (and any code/config baked into it) readable by anyone.")


def _apigw_method(ctx: _Ctx, b: Block) -> None:
    if _lit(b, "authorization") == "NONE" and _lit(b, "http_method") != "OPTIONS" and _bool(b, "api_key_required") is not True:
        ctx.add(b, "TF-API-001", "medium", "API Gateway method with no authorization",
                "authorization = \"NONE\" and no API key. Confirm this endpoint is intentionally public "
                "or that the backend authenticates the caller.", _line(b, "authorization"), confidence="REVIEW")


def _apigw2_route(ctx: _Ctx, b: Block) -> None:
    at = _lit(b, "authorization_type")
    if (at is None or at == "NONE") and not (_lit(b, "route_key") or "").startswith("OPTIONS"):
        ctx.add(b, "TF-API-001", "medium", "API Gateway v2 route with no authorizer",
                "authorization_type is NONE (the default). Confirm the route is intentionally public.",
                confidence="REVIEW")


def _apigw_method_settings(ctx: _Ctx, b: Block) -> None:
    s = b.block("settings")
    if s and _bool(s, "data_trace_enabled") is True:
        ctx.add(b, "TF-API-002", "medium", "API Gateway full request/response logging enabled",
                "data_trace_enabled logs full request and response bodies (tokens, PII) to CloudWatch. "
                "Disable it in production.", s.line)


def _apigw_domain(ctx: _Ctx, b: Block) -> None:
    if _lit(b, "security_policy") == "TLS_1_0":
        ctx.add(b, "TF-TLS-001", "medium", "API Gateway domain allows TLS 1.0",
                "Set security_policy = \"TLS_1_2\".", _line(b, "security_policy"))


def _kms(ctx: _Ctx, b: Block) -> None:
    spec = _lit(b, "customer_master_key_spec") or _lit(b, "key_spec") or "SYMMETRIC_DEFAULT"
    if spec == "SYMMETRIC_DEFAULT" and _bool(b, "enable_key_rotation") is not True:
        ctx.add(b, "TF-KMS-001", "low", "KMS key rotation not enabled",
                "Set enable_key_rotation = true for symmetric customer-managed keys.")


def _cloudtrail(ctx: _Ctx, b: Block) -> None:
    if _bool(b, "enable_log_file_validation") is not True:
        ctx.add(b, "TF-LOG-001", "low", "CloudTrail log file validation disabled",
                "Without digest files, tampering with delivered logs can't be detected.")
    if _bool(b, "is_multi_region_trail") is not True:
        ctx.add(b, "TF-LOG-002", "low", "CloudTrail trail is single-region",
                "Activity in other regions (a common place for attackers to operate) isn't recorded.")
    if not b.attr("kms_key_id"):
        ctx.add(b, "TF-LOG-003", "low", "CloudTrail logs not encrypted with a KMS key", "Set kms_key_id.")


def _log_group(ctx: _Ctx, b: Block) -> None:
    if not b.attr("kms_key_id"):
        ctx.add(b, "TF-LOG-004", "info", "CloudWatch log group not encrypted with a customer KMS key",
                "Consider kms_key_id for log groups that may contain sensitive data (Lambda/API logs).")


def _sqs(ctx: _Ctx, b: Block) -> None:
    if not b.attr("kms_master_key_id") and _bool(b, "sqs_managed_sse_enabled") is False:
        ctx.add(b, "TF-ENC-002", "low", "SQS queue encryption explicitly disabled",
                "Set sqs_managed_sse_enabled = true or kms_master_key_id.")


def _sns(ctx: _Ctx, b: Block) -> None:
    if not b.attr("kms_master_key_id"):
        ctx.add(b, "TF-ENC-002", "low", "SNS topic not encrypted", "Set kms_master_key_id.")


def _ssm_param(ctx: _Ctx, b: Block) -> None:
    name = (_lit(b, "name") or ".".join(b.labels)).lower()
    if _lit(b, "type") == "String" and _SECRETISH_NAME.search(name):
        ctx.add(b, "TF-SEC-002", "medium", "Secret-looking SSM parameter stored as plain String",
                "Use type = \"SecureString\" (with a KMS key) so the value is encrypted at rest and "
                "reading it requires kms:Decrypt.", _line(b, "type"))
    if b.attr("value") and b.attr("value").literal():
        ctx.add(b, "TF-SEC-001", "high" if _SECRETISH_NAME.search(name) else "low",
                "SSM parameter value hardcoded in Terraform",
                "The value is committed to source and stored in state. Set it out-of-band (or via a "
                "sensitive variable fed from the CI secret store) and use lifecycle ignore_changes.",
                _line(b, "value"))


def _secret_version(ctx: _Ctx, b: Block) -> None:
    a = b.attr("secret_string")
    if a and (a.literal() is not None or a.value.strip().startswith("jsonencode")) and not re.search(r"\bvar\.|random_password|data\.", a.value):
        ctx.add(b, "TF-SEC-001", "high", "Secrets Manager secret value hardcoded",
                "The secret is committed to source. Generate it (random_password / RDS-managed) or "
                "set it outside Terraform.", a.line)
    elif a:
        ctx.add(b, "TF-SEC-003", "info", "Secret value passes through Terraform state",
                "secret_string is stored in plaintext in state -- make sure the state backend is "
                "encrypted and access-restricted.", a.line, confidence="REVIEW")


def _ecr(ctx: _Ctx, b: Block) -> None:
    if _lit(b, "image_tag_mutability") != "IMMUTABLE":
        ctx.add(b, "TF-ECR-001", "low", "ECR tags are mutable",
                "A pushed tag can be silently replaced with a different image. Set image_tag_mutability = \"IMMUTABLE\".")
    scan = b.block("image_scanning_configuration")
    if _bool(scan, "scan_on_push") is not True:
        ctx.add(b, "TF-ECR-002", "low", "ECR scan on push disabled",
                "Enable image_scanning_configuration { scan_on_push = true } (or registry-level enhanced scanning).")


def _cloudfront(ctx: _Ctx, b: Block) -> None:
    for blk in b.blocks("default_cache_behavior") + b.blocks("ordered_cache_behavior"):
        if _lit(blk, "viewer_protocol_policy") == "allow-all":
            ctx.add(b, "TF-TLS-002", "medium", "CloudFront allows plain HTTP",
                    "viewer_protocol_policy = \"allow-all\"; use redirect-to-https or https-only.", blk.line)
    if not b.block("logging_config"):
        ctx.add(b, "TF-LOG-008", "low", "CloudFront access logging not configured",
                "Add logging_config (or a v2 log delivery) so edge requests can be investigated.")
    vc = b.block("viewer_certificate")
    mpv = _lit(vc, "minimum_protocol_version") if vc else None
    if mpv and re.match(r"(SSLv3|TLSv1(_2016|\.1_2016)?)$", mpv):
        ctx.add(b, "TF-TLS-001", "medium", f"CloudFront minimum TLS version {mpv}",
                "Use TLSv1.2_2021 or later.", vc.line)


def _lb_listener(ctx: _Ctx, b: Block) -> None:
    proto = _lit(b, "protocol")
    if proto == "HTTP":
        redirects = any(_lit(a, "type") == "redirect" for a in b.blocks("default_action"))
        if not redirects:
            ctx.add(b, "TF-TLS-002", "medium", "Load balancer listener serves plain HTTP",
                    "The listener forwards HTTP traffic instead of redirecting to HTTPS.", _line(b, "protocol"))
    pol = _lit(b, "ssl_policy")
    if pol and _OLD_ELB_TLS.search(pol):
        ctx.add(b, "TF-TLS-001", "medium", f"Load balancer TLS policy allows TLS < 1.2: {pol}",
                "Use ELBSecurityPolicy-TLS13-1-2-2021-06 (or a FIPS variant if FIPS is in scope).",
                _line(b, "ssl_policy"))


def _lb(ctx: _Ctx, b: Block) -> None:
    lt = _lit(b, "load_balancer_type") or "application"
    if lt == "application" and _bool(b, "drop_invalid_header_fields") is not True:
        ctx.add(b, "TF-NET-005", "low", "ALB does not drop invalid HTTP header fields",
                "Set drop_invalid_header_fields = true to reduce request-smuggling/header-injection exposure.")
    if _bool(b.block("access_logs"), "enabled") is not True:
        ctx.add(b, "TF-LOG-007", "low", "Load balancer access logs disabled",
                "Without access_logs { enabled = true } there's no record of who hit what -- "
                "detection and incident scoping both depend on it.")


def _apigw_stage(ctx: _Ctx, b: Block) -> None:
    if not b.block("access_log_settings"):
        ctx.add(b, "TF-LOG-006", "low", "API Gateway stage has no access logging",
                "Add access_log_settings (destination_arn + format) so requests can be investigated.")


def _eks(ctx: _Ctx, b: Block) -> None:
    vpc = b.block("vpc_config")
    if vpc is not None and _bool(vpc, "endpoint_public_access") is not False:
        cidrs = _list_literals(vpc.attr("public_access_cidrs"))
        if not cidrs or _public_cidr(cidrs):
            ctx.add(b, "TF-EKS-001", "medium", "EKS API endpoint public to the internet",
                    "endpoint_public_access defaults to true with 0.0.0.0/0. Disable it or restrict public_access_cidrs.",
                    vpc.line)
    if not b.block("encryption_config"):
        ctx.add(b, "TF-EKS-002", "low", "EKS secrets not envelope-encrypted with KMS",
                "Add encryption_config { resources = [\"secrets\"] ... }.")


def _iam_user_policy(ctx: _Ctx, b: Block) -> None:
    ctx.add(b, "TF-IAM-001", "low", "Policy attached directly to an IAM user",
            "Attach permissions to groups or roles; per-user policies drift and are hard to audit.")


def _policy_attachment(ctx: _Ctx, b: Block) -> None:
    arn = (b.attr("policy_arn").value if b.attr("policy_arn") else "")
    m = re.search(r"policy/(AdministratorAccess|PowerUserAccess|IAMFullAccess|AmazonS3FullAccess|"
                  r"SecretsManagerReadWrite|AWSLambda_FullAccess|AmazonEC2FullAccess)\b", arn)
    if m:
        sev = "high" if m.group(1) in ("AdministratorAccess", "IAMFullAccess", "PowerUserAccess") else "medium"
        ctx.add(b, "TF-IAM-002", sev, f"Broad AWS-managed policy attached: {m.group(1)}",
                "AWS-managed *FullAccess / admin policies grant far more than a workload needs. "
                "Replace with a scoped customer-managed policy.", _line(b, "policy_arn"))
    if b.labels[0] == "aws_iam_user_policy_attachment":
        _iam_user_policy(ctx, b)


def _access_key(ctx: _Ctx, b: Block) -> None:
    ctx.add(b, "TF-IAM-003", "medium" if b.attr("pgp_key") else "high", "Long-lived IAM access key created by Terraform",
            "Static keys don't expire and, " + ("even with pgp_key, " if b.attr("pgp_key") else "without pgp_key, ")
            + "the secret ends up in Terraform state" + ("" if b.attr("pgp_key") else " in plaintext")
            + ". Prefer roles / OIDC federation (e.g. GitLab id_tokens -> AssumeRoleWithWebIdentity).")


def _login_profile(ctx: _Ctx, b: Block) -> None:
    if not b.attr("pgp_key"):
        ctx.add(b, "TF-IAM-004", "low", "IAM login profile without pgp_key",
                "The generated console password is stored in plaintext in state.")


def _password_policy(ctx: _Ctx, b: Block) -> None:
    a = b.attr("minimum_password_length")
    n = a.as_number() if a else None
    if n is not None and n < 14:
        ctx.add(b, "TF-IAM-005", "low", f"IAM password policy minimum length {int(n)}",
                "Use at least 14 characters (CIS AWS Foundations).", a.line)


def _vpc(ctx: _Ctx, b: Block) -> None:
    ref = f"aws_vpc.{b.labels[1]}." if len(b.labels) > 1 else None
    has_flow = any(ref and ref in (fl.attr("vpc_id").value if fl.attr("vpc_id") else "") for fl in ctx.by_type.get("aws_flow_log", []))
    if not has_flow:
        ctx.add(b, "TF-NET-006", "low", "VPC has no flow logs",
                "No aws_flow_log references this VPC -- network forensics won't be possible.")


def _subnet(ctx: _Ctx, b: Block) -> None:
    if _bool(b, "map_public_ip_on_launch") is True:
        ctx.add(b, "TF-NET-007", "low", "Subnet auto-assigns public IPs",
                "Everything launched here gets a public IP by default.", _line(b, "map_public_ip_on_launch"))


def _container_defs(b: Block) -> list[dict]:
    a = b.attr("container_definitions")
    if not a:
        return []
    from checks.hcl import expr_to_py, heredoc_body
    v = a.value.strip()
    data = expr_to_py(v) if v.startswith(("jsonencode", "[")) else None
    if data is None:
        body = heredoc_body(v)
        if body is not None:
            data = iam_policy._parse_jsonish(body)
    if data is None:
        fp = tf_graph._file_path(v, b.file.parent.resolve())
        if fp is not None and fp.is_file():
            data = iam_policy._parse_jsonish(fp.read_text(encoding="utf-8", errors="replace"))
    return [c for c in data if isinstance(c, dict)] if isinstance(data, list) else []


def _ecs_task(ctx: _Ctx, b: Block) -> None:
    line = _line(b, "container_definitions")
    for c in _container_defs(b):
        cname = c.get("name", "?")
        if c.get("privileged") is True:
            ctx.add(b, "TF-ECS-001", "high", f"ECS container '{cname}' runs privileged",
                    "A privileged container has full access to the host's devices and kernel capabilities; "
                    "an RCE in it is a host (and on EC2, instance-role) compromise.", line)
        env_names = [e.get("name", "") for e in c.get("environment", []) or [] if isinstance(e, dict)]
        secretish = [n for n in env_names if _SECRETISH_NAME.search(str(n))]
        if secretish:
            ctx.add(b, "TF-ECS-002", "medium", f"Secret-looking plaintext env vars in ECS container '{cname}': "
                    + ", ".join(secretish[:4]),
                    "`environment` values are visible to anyone with ecs:DescribeTaskDefinition and are stored in "
                    "state. Use the container `secrets` block (valueFrom Secrets Manager / SSM SecureString).", line)
    if _lit(b, "network_mode") == "host" or _lit(b, "pid_mode") == "host":
        ctx.add(b, "TF-ECS-003", "medium", "ECS task shares the host network/PID namespace",
                "network_mode/pid_mode = \"host\" removes container isolation from the host's network "
                "stack or processes.", _line(b, "network_mode") if b.attr("network_mode") else _line(b, "pid_mode"))


def _codebuild(ctx: _Ctx, b: Block) -> None:
    env = b.block("environment")
    if env is None:
        return
    if _bool(env, "privileged_mode") is True:
        ctx.add(b, "TF-CB-001", "low", "CodeBuild project runs in privileged mode",
                "Needed for Docker builds, but a malicious build (e.g. from a pull request source) gets "
                "root on the build host. Restrict which sources/branches can trigger it.",
                _line(env, "privileged_mode"), confidence="REVIEW")
    for ev in env.blocks("environment_variable"):
        name = _lit(ev, "name") or ""
        vtype = _lit(ev, "type") or "PLAINTEXT"
        if vtype == "PLAINTEXT" and _SECRETISH_NAME.search(name) and _lit(ev, "value"):
            ctx.add(b, "TF-CB-002", "medium", f"CodeBuild plaintext environment variable '{name}'",
                    "PLAINTEXT values are visible in the console/API and state. Use type = "
                    "\"SECRETS_MANAGER\" or \"PARAMETER_STORE\".", ev.line)


def _efs(ctx: _Ctx, b: Block) -> None:
    if _bool(b, "encrypted") is not True:
        ctx.add(b, "TF-ENC-003", "medium", "EFS file system not encrypted at rest",
                "Set encrypted = true (with kms_key_id). Encryption can't be added after creation.")


def _kinesis(ctx: _Ctx, b: Block) -> None:
    if _lit(b, "encryption_type") != "KMS":
        ctx.add(b, "TF-ENC-004", "low", "Kinesis stream not encrypted with KMS",
                "Set encryption_type = \"KMS\" and kms_key_id.")


def _firehose(ctx: _Ctx, b: Block) -> None:
    if _bool(b.block("server_side_encryption"), "enabled") is not True:
        ctx.add(b, "TF-ENC-004", "low", "Firehose delivery stream without server-side encryption",
                "Add server_side_encryption { enabled = true }.")


def _dynamodb(ctx: _Ctx, b: Block) -> None:
    if _bool(b.block("point_in_time_recovery"), "enabled") is not True:
        ctx.add(b, "TF-DB-010", "low", "DynamoDB point-in-time recovery disabled",
                "Without PITR, a bad write or delete can't be rolled back.")


def _sfn(ctx: _Ctx, b: Block) -> None:
    lc = b.block("logging_configuration")
    if lc is None or (_lit(lc, "level") or "OFF") == "OFF":
        ctx.add(b, "TF-LOG-009", "low", "Step Functions state machine logging off",
                "Set logging_configuration { level = \"ERROR\" (or ALL), log_destination = ... }.",
                lc.line if lc else None)


def _iam_role(ctx: _Ctx, b: Block) -> None:
    a = b.attr("max_session_duration")
    n = a.as_number() if a else None
    if n is not None and n > 3600:
        ctx.add(b, "TF-IAM-006", "low", f"Role sessions last up to {int(n // 3600)}h",
                "Stolen session credentials stay valid for the whole window. Keep federated/CI role "
                "sessions at the 1h default unless a job genuinely needs longer.", a.line)


def _oidc_provider(ctx: _Ctx, b: Block) -> None:
    url = _lit(b, "url") or ""
    if url.startswith("http://"):
        ctx.add(b, "TF-OIDC-002", "high", "OIDC provider configured over plain HTTP",
                "Token signing keys are fetched without TLS -- an attacker on the path can supply their "
                "own keys and mint tokens for any role trusting this provider.", _line(b, "url"))
    if "*" in _list_literals(b.attr("client_id_list")):
        ctx.add(b, "TF-OIDC-002", "medium", "OIDC provider accepts any audience",
                "client_id_list contains \"*\". Pin the expected audience(s).", _line(b, "client_id_list"))


_RESOURCE_CHECKS: dict[str, Callable[[_Ctx, Block], None]] = {
    "aws_ecs_task_definition": _ecs_task,
    "aws_codebuild_project": _codebuild,
    "aws_efs_file_system": _efs,
    "aws_kinesis_stream": _kinesis,
    "aws_kinesis_firehose_delivery_stream": _firehose,
    "aws_dynamodb_table": _dynamodb,
    "aws_sfn_state_machine": _sfn,
    "aws_iam_role": _iam_role,
    "aws_iam_openid_connect_provider": _oidc_provider,
    "aws_s3_bucket": _s3_bucket,
    "aws_s3_bucket_acl": _s3_bucket_acl,
    "aws_s3_bucket_public_access_block": _s3_pab,
    "aws_s3_account_public_access_block": _s3_pab,
    "aws_s3_bucket_cors_configuration": _s3_cors,
    "aws_s3_bucket_website_configuration": _s3_website,
    "aws_security_group": _sg,
    "aws_default_security_group": _sg,
    "aws_security_group_rule": _sg_rule,
    "aws_vpc_security_group_ingress_rule": _sg_rule,
    "aws_instance": _instance,
    "aws_launch_template": _instance,
    "aws_ebs_volume": _ebs,
    "aws_db_instance": _rds,
    "aws_rds_cluster": _rds,
    "aws_redshift_cluster": _rds,
    "aws_elasticache_replication_group": _elasticache,
    "aws_opensearch_domain": _opensearch,
    "aws_elasticsearch_domain": _opensearch,
    "aws_lambda_function": _lambda,
    "aws_lambda_function_url": _lambda_url,
    "aws_lambda_permission": _lambda_permission,
    "aws_lambda_layer_version_permission": _layer_permission,
    "aws_api_gateway_method": _apigw_method,
    "aws_apigatewayv2_route": _apigw2_route,
    "aws_api_gateway_method_settings": _apigw_method_settings,
    "aws_api_gateway_stage": _apigw_stage,
    "aws_apigatewayv2_stage": _apigw_stage,
    "aws_api_gateway_domain_name": _apigw_domain,
    "aws_kms_key": _kms,
    "aws_cloudtrail": _cloudtrail,
    "aws_cloudwatch_log_group": _log_group,
    "aws_sqs_queue": _sqs,
    "aws_sns_topic": _sns,
    "aws_ssm_parameter": _ssm_param,
    "aws_secretsmanager_secret_version": _secret_version,
    "aws_ecr_repository": _ecr,
    "aws_cloudfront_distribution": _cloudfront,
    "aws_lb_listener": _lb_listener,
    "aws_alb_listener": _lb_listener,
    "aws_lb": _lb,
    "aws_alb": _lb,
    "aws_eks_cluster": _eks,
    "aws_iam_user_policy": _iam_user_policy,
    "aws_iam_policy_attachment": _policy_attachment,
    "aws_iam_role_policy_attachment": _policy_attachment,
    "aws_iam_user_policy_attachment": _policy_attachment,
    "aws_iam_group_policy_attachment": _policy_attachment,
    "aws_iam_access_key": _access_key,
    "aws_iam_user_login_profile": _login_profile,
    "aws_iam_account_password_policy": _password_policy,
    "aws_vpc": _vpc,
    "aws_subnet": _subnet,
}


# ── policies inside Terraform ──────────────────────────────────────────────

def _emit_policy_issues(ctx: _Ctx, b: Block, doc, line: int, stmt_lines: Optional[list[int]] = None) -> None:
    for issue in iam_policy.check_policy(doc):
        at = line
        if stmt_lines and 0 <= issue.statement_index < len(stmt_lines):
            at = stmt_lines[issue.statement_index]
        ctx.add(b, issue.id, issue.severity, issue.title, issue.note, at, issue.confidence)


def _check_resource_policies(ctx: _Ctx, b: Block) -> None:
    rtype = b.labels[0]
    attr_name = _POLICY_ATTRS.get(rtype)
    attrs = []
    if attr_name and b.attr(attr_name):
        attrs.append(b.attr(attr_name))
    for inline in b.blocks("inline_policy"):
        if inline.attr("policy"):
            attrs.append(inline.attr("policy"))
    for a in attrs:
        doc = load_policy_value(a.value)
        if doc is None or not iam_policy.looks_like_policy(doc):
            continue
        # A trust policy doesn't need Version/TLS-style document checks to be
        # noisy about Resource -- check_policy handles both shapes.
        _emit_policy_issues(ctx, b, doc, a.line)


def _check_policy_document_data(ctx: _Ctx, b: Block) -> None:
    doc, lines = tf_graph.policy_doc_from_data(b)
    if doc is not None:
        _emit_policy_issues(ctx, b, doc, b.line, lines)


def _check_provisioners(ctx: _Ctx, b: Block) -> None:
    for p in b.blocks("provisioner"):
        kind = p.labels[0] if p.labels else ""
        if kind not in ("local-exec", "remote-exec"):
            continue
        cmd = p.attr("command") or p.attr("inline")
        interp = cmd and re.search(r"\$\{\s*(var|each|data|local)\.", cmd.value)
        ctx.add(b, "TF-EXEC-001", "medium" if interp else "info",
                f"{kind} provisioner" + (" interpolates variables into a shell command" if interp else ""),
                "Provisioners run arbitrary shell on the CI runner (local-exec) or target host. "
                + ("Interpolated values are not shell-escaped -- a variable containing ; or $(...) "
                   "becomes command injection. Pass values via `environment = {}` and quote them. "
                   if interp else "")
                + "Confirm what the command does and which credentials it runs with.",
                p.line, confidence="REVIEW")


# ── provider / terraform / module / variable / output ──────────────────────

def _check_provider(ctx: _Ctx, b: Block) -> None:
    for name in ("access_key", "secret_key", "token"):
        a = b.attr(name)
        if a and a.literal():
            ctx.add(b, "TF-PROV-001", "high", f"Static credential in provider block ({name})",
                    "Credentials are committed and will be used by everyone running this config. "
                    "Use the default credential chain / assume_role / OIDC instead.", a.line)
    if _bool(b, "insecure") is True or _bool(b, "skip_tls_verify") is True:
        ctx.add(b, "TF-PROV-002", "medium", "Provider TLS verification disabled",
                "insecure / skip_tls_verify allows a man-in-the-middle to read credentials and alter API calls.")


def _check_terraform_block(ctx: _Ctx, b: Block) -> None:
    for backend in b.blocks("backend"):
        btype = backend.labels[0] if backend.labels else ""
        if btype == "s3":
            if _bool(backend, "encrypt") is not True:
                ctx.add(b, "TF-STATE-001", "medium", "S3 state backend without encrypt = true",
                        "Terraform state holds every secret the config touches in plaintext. Set "
                        "encrypt = true (and kms_key_id), and restrict the bucket to the CI role.",
                        backend.line)
            if not backend.attr("dynamodb_table") and _bool(backend, "use_lockfile") is not True:
                ctx.add(b, "TF-STATE-002", "low", "S3 state backend without locking",
                        "Concurrent pipelines can corrupt state. Set use_lockfile = true (TF >= 1.10) or dynamodb_table.",
                        backend.line)
        elif btype == "local":
            ctx.add(b, "TF-STATE-003", "low", "Local state backend",
                    "State (with plaintext secrets) is written next to the code and is easy to commit "
                    "or leave in CI artifacts. Use a remote, encrypted backend.", backend.line)
        elif btype == "http" and re.search(r'"http://', backend.text):
            ctx.add(b, "TF-STATE-004", "high", "HTTP state backend over plain HTTP",
                    "State and the backend credentials travel unencrypted.", backend.line)
    rp = b.block("required_providers")
    if rp:
        for name, a in rp.attrs.items():
            if "version" not in a.value and not re.search(r'^\s*"[^"]*"\s*$', a.value):
                ctx.add(b, "TF-SUP-003", "low", f"Provider '{name}' has no version constraint",
                        "An unpinned provider upgrades on the next init. Pin a version range and commit "
                        ".terraform.lock.hcl.", a.line)


def _check_module(ctx: _Ctx, b: Block) -> None:
    src_attr = b.attr("source")
    src = src_attr.literal() if src_attr else None
    if not src:
        return
    if src.startswith(("./", "../")):
        return
    is_git = src.startswith(("git::", "git@")) or re.match(r"(github\.com|gitlab\.com|bitbucket\.org)/", src) \
        or ".git" in src
    if is_git:
        m = re.search(r"[?&]ref=([^&]+)", src)
        if not m:
            ctx.add(b, "TF-SUP-001", "medium", "Git module source not pinned to a ref",
                    "Without ?ref=, every init pulls the default branch -- whoever can push there "
                    "controls what your pipeline applies. Pin to a commit SHA (or at least a tag).",
                    src_attr.line)
        elif not re.fullmatch(r"[0-9a-f]{40}", m.group(1)):
            branchy = m.group(1) in ("main", "master", "develop", "dev", "HEAD", "trunk")
            ctx.add(b, "TF-SUP-001", "medium" if branchy else "info",
                    f"Git module pinned to {'a branch' if branchy else 'a tag'} ({m.group(1)}), not a commit",
                    "Branches move and tags can be re-pointed. Pin to a full commit SHA for "
                    "supply-chain integrity.", src_attr.line, None if branchy else "REVIEW")
    elif src.startswith(("http://", "s3::http://")):
        ctx.add(b, "TF-SUP-002", "high", "Module downloaded over plain HTTP",
                "A network attacker can swap the module contents.", src_attr.line)
    elif re.fullmatch(r"[\w.-]+(/[\w.-]+){2,3}", src) and not b.attr("version"):
        ctx.add(b, "TF-SUP-001", "medium", "Registry module without a version constraint",
                "Every init may pull a newer, unreviewed release. Add version = \"x.y.z\".", src_attr.line)


# Names that mention a secret but hold metadata about it (ARNs, ids, policy
# settings, flags), checked on a word basis: minimum_password_length,
# task_exec_secret_arns, create_access_key, iam_access_key_id...
_NOT_A_SECRET_NAME = re.compile(
    r"(?i)(?:^|_|(?<=[a-z])(?=[A-Z]))(?:arns?|ids?|fingerprint|status|encrypted|policy|policies|expire\w*|length|age|"
    r"reuse|prevention|rotation|ttl|version|names?|paths?|specs?|type|kms|count|days|reset|required|enabled|"
    r"recovery|window|identifier|source|location|ref|uri|url|header|parameter|wo_version)(?:_|$|(?=[A-Z]))"
    r"|^(?:create|allow|enable|manage|use|include|attach|rotate|generate|is|has|should|max|min|minimum|maximum)_")


def _secret_name(name: str) -> bool:
    return bool(_SECRETISH_NAME.search(name)) and not _NOT_A_SECRET_NAME.search(name)


def _check_variable(ctx: _Ctx, b: Block) -> None:
    name = b.labels[0] if b.labels else ""
    if not _secret_name(name):
        return
    vtype = (b.attr("type").value.strip() if b.attr("type") else "")
    dflt = b.attr("default").value.strip() if b.attr("default") else ""
    if vtype in ("bool", "number") or re.fullmatch(r"true|false|-?\d+(?:\.\d+)?", dflt):
        return
    if _bool(b, "sensitive") is not True:
        ctx.add(b, "TF-VAR-001", "low", f"Secret-looking variable '{name}' not marked sensitive",
                "Without sensitive = true the value is printed in plan/apply output and CI logs.")
    d = b.attr("default")
    if d and d.literal():
        ctx.add(b, "TF-VAR-002", "high", f"Secret-looking variable '{name}' has a literal default",
                "The default is committed to source. Remove it and supply the value from the CI secret "
                "store (TF_VAR_...).", d.line)


def _check_output(ctx: _Ctx, b: Block) -> None:
    name = b.labels[0] if b.labels else ""
    value = b.attr("value").value if b.attr("value") else ""
    if (_secret_name(name) or re.search(r"\.(password|secret|private_key|secret_string|token|"
                                        r"secret_access_key|private_key_pem|ses_smtp_password_v4)\b", value)) \
            and _bool(b, "sensitive") is not True:
        ctx.add(b, "TF-VAR-003", "medium", f"Output '{name}' exposes a secret without sensitive = true",
                "The value is printed in apply output / CI logs and returned by `terraform output`.")


# ── project-wide ───────────────────────────────────────────────────────────

_TAGGABLE_PREFIXES = ("aws_s3_bucket", "aws_instance", "aws_db_instance", "aws_rds_cluster", "aws_lambda_function",
                      "aws_vpc", "aws_subnet", "aws_security_group", "aws_kms_key", "aws_iam_role", "aws_eks_cluster",
                      "aws_dynamodb_table", "aws_sqs_queue", "aws_sns_topic", "aws_lb", "aws_ecr_repository",
                      "aws_secretsmanager_secret", "aws_cloudwatch_log_group", "aws_ebs_volume")


def _asset_checks(ctx: _Ctx) -> None:
    aws_providers = [b for b in ctx.by_type.get("provider", []) if b.labels and b.labels[0] == "aws"]
    has_default_tags = any(p.block("default_tags") for p in aws_providers)
    if has_default_tags:
        return
    untagged = [
        b for b in ctx.blocks
        if b.kind == "resource" and b.labels and b.labels[0] in _TAGGABLE_PREFIXES and not b.attr("tags")
    ]
    if not untagged:
        return
    anchor = aws_providers[0] if aws_providers else untagged[0]
    ctx.findings.append(make_finding(
        "TF-ASSET-001", "low", f"{len(untagged)} resource(s) with no tags and no provider default_tags",
        "Without owner / environment / data-classification tags, resources can't be tied back to a "
        "team, prioritized by criticality, or found during incident response. Add provider "
        "default_tags { tags = { Owner, Environment, DataClassification, ... } }. First untagged: "
        + ", ".join(".".join(b.labels) for b in untagged[:5]),
        rel(anchor.file, ctx.root), anchor.line,
    ))


def _detection_checks(ctx: _Ctx) -> None:
    """Account-baseline detective controls. Only meaningful when the scanned
    config looks like it manages account-level resources (a trail, an
    organization, a Config recorder...), otherwise any workload repo would
    be flagged for not containing GuardDuty."""
    baseline_markers = ("aws_cloudtrail", "aws_organizations_organization", "aws_config_configuration_recorder",
                        "aws_securityhub_account", "aws_guardduty_detector", "aws_iam_account_password_policy",
                        "aws_s3_account_public_access_block", "aws_ebs_encryption_by_default")
    present = [m for m in baseline_markers if ctx.by_type.get(m)]
    if not present:
        return
    anchor = ctx.by_type[present[0]][0]
    for rtype, label in (("aws_guardduty_detector", "GuardDuty"), ("aws_config_configuration_recorder", "AWS Config"),
                         ("aws_securityhub_account", "Security Hub")):
        if not ctx.by_type.get(rtype):
            ctx.findings.append(make_finding(
                "TF-LOG-005", "low", f"Account baseline without {label}",
                f"This config manages account-level controls ({present[0]}) but never enables {label}. "
                "Confirm it's enabled elsewhere (org-level delegated admin, another stack) -- otherwise "
                "threat detection / configuration drift goes unmonitored.",
                rel(anchor.file, ctx.root), anchor.line, "REVIEW",
            ))


def _waf_checks(ctx: _Ctx) -> None:
    """Internet-facing ALBs / API stages with no WAF association."""
    assoc_text = " ".join((a.attr("resource_arn").value if a.attr("resource_arn") else "")
                          for a in ctx.by_type.get("aws_wafv2_web_acl_association", []) +
                          ctx.by_type.get("aws_wafregional_web_acl_association", []))
    targets = [b for t in ("aws_lb", "aws_alb") for b in ctx.by_type.get(t, [])
               if (_lit(b, "load_balancer_type") or "application") == "application" and _bool(b, "internal") is not True]
    targets += ctx.by_type.get("aws_api_gateway_stage", [])
    for b in targets:
        if len(b.labels) > 1 and f"{b.labels[0]}.{b.labels[1]}." not in assoc_text:
            ctx.add(b, "TF-NET-008", "low", "Internet-facing endpoint without a WAF web ACL",
                    "No aws_wafv2_web_acl_association targets this resource. Confirm WAF is applied "
                    "elsewhere (Firewall Manager, another stack) if the endpoint takes untrusted traffic.",
                    confidence="REVIEW")
    for b in ctx.by_type.get("aws_cloudfront_distribution", []):
        if not b.attr("web_acl_id"):
            ctx.add(b, "TF-NET-008", "low", "CloudFront distribution without a WAF web ACL",
                    "Set web_acl_id if the distribution fronts an application.", confidence="REVIEW")


def _gitlab_trust_checks(ctx: _Ctx) -> None:
    root = ctx.root
    for t in ctx.proj.gitlab_trusts:
        r = t.role
        if not t.subs:
            continue  # POL-009 (high) already reports "no sub condition"
        if not (t.any_ref or t.any_project):
            continue
        scope = "any project in the matched group/instance" if t.any_project else "any branch or merge request of the project"
        sev = "high" if (r.privileged or r.can_write) else "medium"
        perms = r.summary(root)
        ctx.add(r.block, "TF-OIDC-001", sev, f"GitLab OIDC role assumable from {scope}",
                f"Trust `sub` = {', '.join(t.subs[:3])}. GitLab issues id_tokens to every pipeline, including "
                "ones for unprotected branches and merge requests, so anyone who can push a branch can run a "
                "job that assumes this role. What they get: " + perms + ". Pin `sub` to protected refs "
                "(e.g. project_path:group/project:ref_type:branch:ref:main) and keep plan-only roles "
                "read-only.")


def _project_checks(ctx: _Ctx) -> None:
    _asset_checks(ctx)
    _detection_checks(ctx)
    _waf_checks(ctx)
    _gitlab_trust_checks(ctx)
    root_dirs: set[Path] = set()
    for b in ctx.blocks:
        if b.kind == "provider" or (b.kind == "terraform" and b.blocks("backend")):
            root_dirs.add(b.file.parent)
    missing = [d for d in sorted(root_dirs) if not (d / ".terraform.lock.hcl").exists()]
    if missing:
        # One finding, not one per examples/ directory.
        real = [d for d in missing if not {"examples", "example", "test", "tests", "fixtures"} & set(d.relative_to(ctx.root).parts)] \
            if all(d.is_relative_to(ctx.root) for d in missing) else missing
        listed = real or missing
        names = ", ".join((rel(d, ctx.root) if d != ctx.root else ".") for d in listed[:6])
        ctx.findings.append(make_finding(
            "TF-SUP-004", "low" if real else "info",
            f"No .terraform.lock.hcl committed for {len(listed)} root module(s)"
            + ("" if real else " (examples/tests only)"),
            "Without the dependency lock file, provider binaries aren't checksum-pinned and "
            "`terraform init` in CI may fetch different builds than were reviewed. Commit it "
            f"(and use `terraform init -lockfile=readonly` in CI). Missing in: {names}"
            + (f" (+{len(listed) - 6} more)" if len(listed) > 6 else "") + ".",
            rel(listed[0], ctx.root) if listed[0] != ctx.root else ".", 1,
        ))


_TF_LINE_RULES = [
    LineRule("TF-TLS-003", "medium", "TLS verification disabled",
             r"(?i)\b(?:insecure_skip_verify|tls_insecure_skip_verify|skip_ssl_verify)\s*=\s*true\b|\bssl_verify\s*=\s*false\b",
             "TLS verification is turned off for this connection -- credentials and data can be "
             "intercepted."),
]
