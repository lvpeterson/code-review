"""Cross-file IaC context: Terraform variable resolution, the project model
(roles, GitLab OIDC trust, Lambda -> role, policy-file links), GitLab job
inheritance + GL-TF-004, the extra resource checks, and osv-scanner parsing."""
from pathlib import Path

from checks import aws_lambda, gitlab_ci, iam_policy, sca, terraform, tf_graph
from checks.gitlab_merge import Registry


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _by_id(findings, cid):
    return [f for f in findings if f.check_id == cid]


# ── variable resolution ────────────────────────────────────────────────────

def test_tfvars_module_input_local_and_ternary_resolution(tmp_path):
    _write(tmp_path, "infra/main.tf", '''
locals { open = var.allow_public }
module "logs" {
  source = "./modules/bucket"
  acl    = local.open ? "public-read" : "private"
}
resource "aws_db_instance" "db" {
  publicly_accessible = var.db_public
  storage_encrypted   = true
  deletion_protection = true
}
''')
    _write(tmp_path, "infra/variables.tf", 'variable "allow_public" { default = false }\n'
                                           'variable "db_public" { default = false }\n')
    _write(tmp_path, "infra/terraform.tfvars", "allow_public = true\n")
    _write(tmp_path, "infra/modules/bucket/main.tf",
           'variable "acl" { default = "private" }\nresource "aws_s3_bucket" "this" {\n  acl = var.acl\n}\n')
    f = terraform.scan_project(tmp_path)
    s3 = _by_id(f, "TF-S3-001")
    assert len(s3) == 1 and s3[0].file.endswith("main.tf") and "bucket" in s3[0].file
    assert "terraform.tfvars:1" in s3[0].description and "module.logs" in s3[0].description
    assert _by_id(f, "TF-DB-001") == []           # db_public only defaults to false


def test_env_tfvars_folder_applies_to_root_and_lists_other_values(tmp_path):
    _write(tmp_path, "main.tf", '''
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }
}
variable "admin_cidrs" { default = ["10.0.0.0/8"] }
''')
    _write(tmp_path, "envs/prod.tfvars", 'admin_cidrs = ["0.0.0.0/0"]\n')
    net = _by_id(terraform.scan_project(tmp_path), "TF-NET-001")
    assert len(net) == 1
    assert "prod.tfvars:1" in net[0].description and "10.0.0.0/8" in net[0].description


def test_unresolvable_references_are_left_alone(tmp_path):
    _write(tmp_path, "main.tf", '''
resource "aws_s3_bucket" "b" {
  acl    = lookup(var.acls, "x")
  bucket = "${var.unset}-logs"
}
variable "acls" { default = { x = "public-read" } }
variable "unset" {}
''')
    proj = tf_graph.load(tmp_path)
    b = proj.by_type["aws_s3_bucket"][0]
    assert b.attr("acl").raw is None and b.attr("bucket").raw is None
    assert _by_id(terraform.scan_project(tmp_path), "TF-S3-001") == []


# ── project model ──────────────────────────────────────────────────────────

_TRUST_TF = '''
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.gitlab.arn]
    }
    condition {
      test     = "StringLike"
      variable = "gitlab.com:sub"
      values   = [var.sub]
    }
    condition {
      test     = "StringEquals"
      variable = "gitlab.com:aud"
      values   = ["https://gitlab.com"]
    }
  }
}
resource "aws_iam_role" "deploy" {
  name               = "terraform-deploy"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}
resource "aws_iam_role_policy" "deploy" {
  role   = aws_iam_role.deploy.id
  policy = file("${path.module}/policies/deploy.json")
}
'''
_ADMIN_JSON = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'


def test_gitlab_trust_any_branch_with_admin_role_is_high(tmp_path):
    _write(tmp_path, "main.tf", _TRUST_TF + 'variable "sub" { default = "project_path:acme/infra:*" }\n')
    _write(tmp_path, "policies/deploy.json", _ADMIN_JSON)
    f = _by_id(terraform.scan_project(tmp_path), "TF-OIDC-001")
    assert len(f) == 1 and f[0].severity == "high" and "Full administrator access" in f[0].description
    pol = _by_id(iam_policy.scan_policy_files(tmp_path), "POL-001")
    assert pol and "aws_iam_role_policy.deploy" in pol[0].description


def test_gitlab_trust_pinned_to_main_is_quiet(tmp_path):
    _write(tmp_path, "main.tf", _TRUST_TF +
           'variable "sub" { default = "project_path:acme/infra:ref_type:branch:ref:main" }\n')
    _write(tmp_path, "policies/deploy.json", _ADMIN_JSON)
    assert _by_id(terraform.scan_project(tmp_path), "TF-OIDC-001") == []
    t = tf_graph.load(tmp_path).gitlab_trusts[0]
    assert not t.any_ref and t.refs == ["branch:main"]


def test_classify_gitlab_subs():
    c = tf_graph.classify_gitlab_subs
    assert c(["project_path:g/p:ref_type:branch:ref:main"]) == (False, False, ["branch:main"])
    assert c(["project_path:g/p:ref_type:branch:ref:*"])[0] is True
    assert c(["project_path:g/*:ref_type:branch:ref:main"])[1] is True
    assert c([]) == (True, True, [])


def test_lambda_findings_get_role_and_trigger_context(tmp_path):
    _write(tmp_path, "infra/main.tf", '''
resource "aws_iam_role" "fn" { name = "fn" }
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.fn.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
data "archive_file" "fn" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "build.zip"
}
resource "aws_lambda_function" "fn" {
  role     = aws_iam_role.fn.arn
  handler  = "app.handler"
  filename = data.archive_file.fn.output_path
}
resource "aws_lambda_function_url" "fn" {
  function_name      = aws_lambda_function.fn.function_name
  authorization_type = "NONE"
}
''')
    _write(tmp_path, "src/app.py", "import os\ndef handler(event, context):\n    os.system(event['c'])\n")
    findings, eps = aws_lambda.scan_project(tmp_path)
    ctx = _by_id(findings, "LMB-019")
    assert len(ctx) == 1 and ctx[0].severity == "high" and "AdministratorAccess" in ctx[0].description
    cmd = [f for f in findings if f.severity == "high" and f.check_id != "LMB-019"]
    assert cmd and all("function URL with no auth" in f.description for f in cmd)
    assert "public:" in eps[0].detail


# ── GitLab inheritance + GL-TF-004 ─────────────────────────────────────────

_CI = '''include:
  - local: /ci/templates.yml
default:
  id_tokens:
    TOKEN:
      aud: https://gitlab.com
variables:
  ROLE_ARN: arn:aws:iam::123456789012:role/terraform-deploy
.mr: &mr
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
plan:
  <<: *mr
  script:
    - ./scripts/plan.sh
apply:
  extends: .tf_apply
  script:
    - terraform apply plan.tfplan
apply_main_only:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  when: manual
  environment: prod
  script:
    - terraform apply plan.tfplan
other:
  extends: .not_in_repo
  script:
    - terraform apply x
'''
_TEMPLATES = '''.tf_base:
  rules:
    - if: $CI_COMMIT_BRANCH
.tf_apply:
  extends: .tf_base
  when: manual
  environment: production
  rules:
    - if: $CI_COMMIT_REF_PROTECTED == "true"
'''


def _gitlab_repo(tmp_path, sub="project_path:acme/infra:*"):
    _write(tmp_path, ".gitlab-ci.yml", _CI)
    _write(tmp_path, "ci/templates.yml", _TEMPLATES)
    _write(tmp_path, "scripts/plan.sh", "#!/bin/bash\nset -euo pipefail\nterraform plan -out plan.tfplan\n")
    _write(tmp_path, "main.tf", _TRUST_TF + f'variable "sub" {{ default = "{sub}" }}\n')
    _write(tmp_path, "policies/deploy.json", _ADMIN_JSON)


def test_gitlab_merges_extends_anchors_and_default(tmp_path):
    _gitlab_repo(tmp_path)
    reg = Registry(tmp_path, list(gitlab_ci.iter_ci_files(tmp_path)))
    plan = reg.effective(reg.jobs["plan"])
    assert "id_tokens" in plan.inherited_keys and gitlab_ci.ref_scope(plan.text) == "mr"
    apply = reg.effective(reg.jobs["apply"])
    assert {"when", "environment", "rules"} <= set(apply.inherited_keys)
    assert gitlab_ci.ref_scope(apply.text) == "protected"
    assert reg.effective(reg.jobs["other"]).unresolved == [".not_in_repo"]


def test_gl_tf_004_matches_job_to_role_trust_and_permissions(tmp_path):
    _gitlab_repo(tmp_path)
    f = gitlab_ci.scan_project(tmp_path)
    gl4 = {x.title.split("'")[1]: x for x in _by_id(f, "GL-TF-004")}
    assert gl4["plan"].severity == "high" and "scripts/plan.sh" in gl4["plan"].title
    assert "terraform-deploy" in gl4["plan"].description and "Full administrator" in gl4["plan"].description
    assert "apply" not in gl4 and "apply_main_only" not in gl4          # protected refs only
    assert gl4["other"].confidence == "REVIEW"                           # template not in the repo
    tf1 = {x.title.split("'")[1] for x in _by_id(f, "GL-TF-001")}
    assert "apply" not in tf1 and "apply_main_only" not in tf1 and "other" in tf1


def test_gl_tf_004_low_when_trust_pinned_to_protected_ref(tmp_path):
    _gitlab_repo(tmp_path, sub="project_path:acme/infra:ref_type:branch:ref:main")
    plan = [x for x in _by_id(gitlab_ci.scan_project(tmp_path), "GL-TF-004") if "'plan'" in x.title]
    assert plan[0].severity == "low" and "branch:main" in plan[0].description


def test_workflow_restricted_to_protected_refs_suppresses_gl_tf_004(tmp_path):
    _gitlab_repo(tmp_path)
    ci = (tmp_path / ".gitlab-ci.yml").read_text()
    _write(tmp_path, ".gitlab-ci.yml", "workflow:\n  rules:\n    - if: $CI_COMMIT_REF_PROTECTED == \"true\"\n" + ci)
    assert _by_id(gitlab_ci.scan_project(tmp_path), "GL-TF-004") == []


def test_ref_scope_conditions():
    rs = gitlab_ci.ref_scope
    assert rs("j:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n") == "protected"
    assert rs("j:\n  rules:\n    - if: $CI_COMMIT_BRANCH == \"main\" || $CI_COMMIT_BRANCH =~ /feat/\n") == "any"
    assert rs("j:\n  rules:\n    - if: $CI_MERGE_REQUEST_IID\n") == "mr"
    assert rs("j:\n  rules:\n    - if: $CI_COMMIT_BRANCH == \"dev\"\n      when: never\n    - when: always\n") == "any"
    assert rs("j:\n  only:\n    - main\n") == "protected"
    assert rs("j:\n  script: [x]\n") == "any"


# ── new resource checks ────────────────────────────────────────────────────

def test_ecs_codebuild_efs_and_oidc_provider(tmp_path):
    _write(tmp_path, "main.tf", '''
resource "aws_ecs_task_definition" "t" {
  network_mode = "host"
  container_definitions = jsonencode([{ name = "app", privileged = true,
    environment = [{ name = "DB_PASSWORD", value = "x" }] }])
}
resource "aws_codebuild_project" "cb" {
  environment {
    privileged_mode = true
    environment_variable {
      name  = "API_TOKEN"
      value = "abc"
    }
  }
}
resource "aws_efs_file_system" "fs" {}
resource "aws_iam_openid_connect_provider" "p" {
  url            = "http://gitlab.internal"
  client_id_list = ["*"]
}
''')
    ids = [f.check_id for f in terraform.scan_project(tmp_path)]
    for cid in ("TF-ECS-001", "TF-ECS-002", "TF-ECS-003", "TF-CB-001", "TF-CB-002", "TF-ENC-003"):
        assert cid in ids, cid
    assert ids.count("TF-OIDC-002") == 2


# ── osv-scanner output ─────────────────────────────────────────────────────

def test_sca_parse_osv_json(tmp_path):
    req = _write(tmp_path, "lambda/requirements.txt", "requests==2.19.0\njinja2==2.10\n")
    data = {"results": [{"source": {"path": str(req), "type": "lockfile"}, "packages": [
        {"package": {"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"},
         "vulnerabilities": [{"id": "GHSA-462w-v97r-4m45", "summary": "sandbox escape",
                              "aliases": ["CVE-2019-10906"], "database_specific": {"severity": "HIGH"}}],
         "groups": [{"ids": ["GHSA-462w-v97r-4m45"], "max_severity": "8.6"}]},
        {"package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"}, "vulnerabilities": []},
    ]}]}
    f = sca.parse(data, tmp_path)
    assert len(f) == 1 and f[0].severity == "high" and "CVE-2019-10906" in f[0].title
    assert f[0].line == 2 and f[0].file.endswith("requirements.txt") and f[0].category.startswith("ISR01")


def test_sca_without_binary_explains_itself(tmp_path, monkeypatch):
    monkeypatch.setattr(sca.shutil, "which", lambda _: None)
    r = sca.run(tmp_path)
    assert r.findings == [] and "osv-scanner isn't on PATH" in r.notes[0]
