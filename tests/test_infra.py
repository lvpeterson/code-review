"""Infrastructure-as-code, crypto and Lambda checks: Terraform, IAM policy
JSON, GitLab CI, shell, repo files, Java/PHP crypto, Lambda taint, OWASP ISR
mapping, and the HTML Infrastructure tab."""
import re
from pathlib import Path

import pytest

from checks import aws_lambda, crypto, gitlab_ci, iam_policy, repo_files, shell, terraform
from checks.hcl import load_policy_value, parse_hcl
from core.html_report import render_html
from core.owasp_isr import isr_for
from enumerator import enumerate_target


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _ids(findings):
    return [f.check_id for f in findings]


def _by_id(findings, cid):
    return [f for f in findings if f.check_id == cid]


# ── HCL parser ──────────────────────────────────────────────────────────────

def test_hcl_parser_handles_nesting_comments_and_braces_in_strings():
    src = (
        '# { not a brace\n'
        'resource "aws_s3_bucket" "b" {\n'
        '  bucket = "x-${var.env}" // trailing {\n'
        '  tags = {\n'
        '    Name = "a { b"\n'
        '  }\n'
        '  versioning {\n'
        '    enabled = false\n'
        '  }\n'
        '}\n'
    )
    [b] = parse_hcl(src, Path("a.tf"))
    assert b.labels == ["aws_s3_bucket", "b"]
    assert (b.line, b.end_line) == (2, 10)
    assert b.attr("bucket").line == 3
    assert b.block("versioning").attr("enabled").as_bool() is False


def test_policy_value_from_jsonencode_and_heredoc():
    j = 'jsonencode({\n  Version = "2012-10-17"\n  Statement = [{ Effect = "Allow", Action = ["s3:*"], Resource = "*" }]\n})'
    assert load_policy_value(j)["Statement"][0]["Action"] == ["s3:*"]
    h = '<<EOF\n{"Statement":[{"Effect":"Allow","Action":"*","Resource":"${aws_s3_bucket.b.arn}"}]}\nEOF'
    assert load_policy_value(h)["Statement"][0]["Action"] == "*"


# ── Terraform ───────────────────────────────────────────────────────────────

def test_terraform_core_misconfigurations(tmp_path):
    _write(tmp_path, "main.tf", '''
resource "aws_s3_bucket" "pub" {
  bucket = "pub"
  acl    = "public-read"
}
resource "aws_security_group" "sg" {
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_instance" "i" {
  ami = "ami-1"
}
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = true
}
resource "aws_lambda_function_url" "u" {
  function_name      = "f"
  authorization_type = "NONE"
}
''')
    f = terraform.scan_project(tmp_path)
    ids = _ids(f)
    for expected in ("TF-S3-001", "TF-S3-002", "TF-NET-001", "TF-EC2-001", "TF-DB-001", "TF-LMB-004"):
        assert expected in ids, expected
    assert "TF-DB-002" not in ids  # storage_encrypted = true
    net = _by_id(f, "TF-NET-001")
    assert len(net) == 1 and "3389" in net[0].title  # 443 isn't an admin port
    assert not _by_id(f, "TF-NET-002")


def test_public_access_block_reference_suppresses_missing_block(tmp_path):
    _write(tmp_path, "s3.tf", '''
resource "aws_s3_bucket" "b" { bucket = "b" }
resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket.b.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
''')
    ids = _ids(terraform.scan_project(tmp_path))
    assert "TF-S3-002" not in ids and "TF-S3-007" not in ids


def test_module_pinning(tmp_path):
    _write(tmp_path, "m.tf", '''
module "a" { source = "git::https://gitlab.com/acme/mods.git//vpc" }
module "b" { source = "git::https://gitlab.com/acme/mods.git//vpc?ref=main" }
module "c" { source = "git::https://gitlab.com/acme/mods.git//vpc?ref=0123456789abcdef0123456789abcdef01234567" }
module "d" { source = "terraform-aws-modules/vpc/aws" }
module "e" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
}
module "f" { source = "./local" }
''')
    sup = _by_id(terraform.scan_project(tmp_path), "TF-SUP-001")
    assert sorted(f.line for f in sup) == [2, 3, 5]


def test_inline_and_data_policy_documents(tmp_path):
    _write(tmp_path, "iam.tf", '''
resource "aws_iam_role" "ci" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/gitlab.com" }
    }]
  })
}
data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["iam:PassRole"]
    resources = ["*"]
  }
}
''')
    f = terraform.scan_project(tmp_path)
    assert any(x.check_id == "POL-009" and x.severity == "high" for x in f)
    privesc = _by_id(f, "POL-004")
    assert privesc and privesc[0].line == 13  # the statement block line


def test_secrets_and_placeholders_in_terraform(tmp_path):
    _write(tmp_path, "s.tf", '''
provider "aws" {
  access_key = "AKIAABCDEFGHIJKLMNOP"
}
resource "aws_db_instance" "db" {
  password = "admin123"
}
resource "aws_db_instance" "db2" {
  password = var.db_password
}
''')
    ids = _ids(terraform.scan_project(tmp_path))
    assert "SECRET-001" in ids and "TF-PROV-001" in ids
    assert "SECRET-006" in ids
    assert ids.count("SECRET-005") == 0  # var. reference isn't a literal


def test_state_backend_and_lock_file(tmp_path):
    _write(tmp_path, "backend.tf", '''
terraform {
  backend "s3" {
    bucket = "x"
  }
}
provider "aws" {}
''')
    ids = _ids(terraform.scan_project(tmp_path))
    assert {"TF-STATE-001", "TF-STATE-002", "TF-SUP-004"} <= set(ids)
    _write(tmp_path, ".terraform.lock.hcl", "# lock")
    assert "TF-SUP-004" not in _ids(terraform.scan_project(tmp_path))


# ── IAM policy JSON ─────────────────────────────────────────────────────────

def test_policy_files_and_statement_lines(tmp_path):
    _write(tmp_path, "p/admin.json", '{\n  "Version": "2012-10-17",\n  "Statement": [\n'
           '    {"Sid": "A", "Effect": "Allow", "Action": "*", "Resource": "*"},\n'
           '    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}\n'
           '  ]\n}\n')
    f = iam_policy.scan_policy_files(tmp_path)
    admin = _by_id(f, "POL-001")[0]
    assert admin.line == 4 and "Sid A" in admin.title
    assert _by_id(f, "POL-005")[0].line == 5
    assert "POL-008" in _ids(f)


def test_bucket_policy_with_tls_deny_and_scoped_principal_is_quiet(tmp_path):
    _write(tmp_path, "bp.json", '''{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:role/app"},
     "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
    {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*",
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
  ]
}''')
    assert iam_policy.scan_policy_files(tmp_path) == []


def test_oidc_sub_wildcard_and_pinned():
    base = {"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {"Federated": "arn:aws:iam::1:oidc-provider/gitlab.com"}}
    wild = dict(base, Condition={"StringLike": {"gitlab.com:sub": "project_path:acme/*:ref_type:branch:ref:*"},
                                 "StringEquals": {"gitlab.com:aud": "https://gitlab.com"}})
    pinned = dict(base, Condition={"StringEquals": {"gitlab.com:sub": "project_path:acme/infra:ref_type:branch:ref:main",
                                                    "gitlab.com:aud": "https://gitlab.com"}})
    w = iam_policy.check_policy({"Version": "2012-10-17", "Statement": [wild]})
    assert [(i.id, i.severity) for i in w] == [("POL-009", "medium")]
    assert iam_policy.check_policy({"Version": "2012-10-17", "Statement": [pinned]}) == []


def test_partial_wildcard_matches_privesc_actions():
    issues = iam_policy.check_policy({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "iam:Put*", "Resource": "arn:aws:iam::1:role/x"}]})
    pe = [i for i in issues if i.id == "POL-004"]
    assert pe and pe[0].severity == "medium" and "iam:PutRolePolicy" in pe[0].title


# ── GitLab CI ───────────────────────────────────────────────────────────────

_CI = '''include:
  - remote: 'https://example.com/t.yml'
  - project: 'acme/templates'
    file: '/x.yml'
  - project: 'acme/pinned'
    ref: 'v1.2.3'
    file: '/x.yml'

variables:
  CI_DEBUG_TRACE: "true"

image: hashicorp/terraform:1.9.0@sha256:abc

plan:
  image: alpine
  script:
    - terraform plan -out=plan.tfplan | tee plan.log
    - echo "$CI_MERGE_REQUEST_TITLE"
  artifacts:
    paths:
      - plan.tfplan

apply:
  script:
    - terraform apply plan.tfplan
  when: manual
  environment: production
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
'''


def test_gitlab_ci_checks(tmp_path):
    _write(tmp_path, ".gitlab-ci.yml", _CI)
    f = gitlab_ci.scan_project(tmp_path)
    ids = _ids(f)
    for expected in ("GL-INC-001", "GL-INC-002", "GL-001", "GL-002", "GL-IMG-001", "GL-TF-003", "GL-012"):
        assert expected in ids, expected
    assert [x.line for x in _by_id(f, "GL-INC-002")] == [3]  # the ref'd include is fine
    assert [x.line for x in _by_id(f, "GL-IMG-001")] == [15]  # digest-pinned image is fine
    assert "GL-TF-001" not in ids and "GL-TF-002" not in ids  # manual + environment


def test_gitlab_apply_without_gate(tmp_path):
    _write(tmp_path, ".gitlab-ci.yml", "stages: [apply]\napply:\n  stage: apply\n  script:\n    - terraform apply -auto-approve\n")
    f = gitlab_ci.scan_project(tmp_path)
    gate = _by_id(f, "GL-TF-001")
    assert gate and gate[0].severity == "medium" and gate[0].line == 5
    assert "SH-007" in _ids(f)


# ── Shell ───────────────────────────────────────────────────────────────────

def test_wrapper_script_exit_status_checks(tmp_path):
    _write(tmp_path, "validate.sh", "#!/bin/bash\nterraform validate || true\nterraform plan | tee out.log\n")
    ids = _ids(shell.scan_project(tmp_path))
    assert {"SH-020", "SH-006", "SH-021"} <= set(ids)


def test_strict_script_is_quiet_and_shebang_detection(tmp_path):
    _write(tmp_path, "bin2/plan", "#!/usr/bin/env bash\nset -euo pipefail\nterraform plan -out tfplan | tee log\n")
    assert list(shell.iter_shell_files(tmp_path))
    assert shell.scan_project(tmp_path) == []


def test_shell_keygen_rules(tmp_path):
    _write(tmp_path, "gen.sh", "#!/bin/sh\nset -e\nopenssl genrsa -out k.pem 1024\n"
                               "openssl enc -aes-256-cbc -in a -out b -pass pass:x\nrm -rf $DIR/\nrm -rf \"${DIR:?}\"/\n")
    f = shell.scan_project(tmp_path)
    assert {"SH-012", "SH-011", "SH-013", "SH-025"} <= set(_ids(f))
    assert [x.line for x in _by_id(f, "SH-022")] == [5]


def test_comment_masking_in_shell(tmp_path):
    _write(tmp_path, "c.sh", "#!/bin/sh\nset -e\n# curl https://x | sh\necho don't do this  # curl x | sh\n"
                             "echo \"a # b\" && curl https://y | sh\n")
    # Comments are masked (including after an apostrophe in prose); a '#'
    # inside a quoted string doesn't start one.
    assert [f.line for f in shell.scan_project(tmp_path) if f.check_id == "SH-001"] == [5]


# ── Repo files ──────────────────────────────────────────────────────────────

def test_repo_files(tmp_path):
    _write(tmp_path, "main.tf", "")
    _write(tmp_path, "terraform.tfstate", "{}")
    _write(tmp_path, "keys/server.pem", "-----BEGIN PRIVATE KEY-----\nabc\n")
    _write(tmp_path, "certs/ca.pem", "-----BEGIN CERTIFICATE-----\nabc\n")
    _write(tmp_path, ".env.example", "X=1")
    ids = _ids(repo_files.scan_project(tmp_path))
    assert ids.count("REPO-001") == 1 and ids.count("REPO-002") == 1
    assert "REPO-003" not in ids and "REPO-005" in ids


# ── Crypto ──────────────────────────────────────────────────────────────────

_JAVA = '''import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
class C {
  void f() throws Exception {
    Security.addProvider(new BouncyCastleFipsProvider());
    Cipher a = Cipher.getInstance("AES/ECB/PKCS5Padding");
    Cipher b = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
    Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    IvParameterSpec iv = new IvParameterSpec(new byte[16]);
    // Cipher.getInstance("DES") in a comment
  }
}
'''


def test_java_crypto_and_bc_fips_project_rules(tmp_path):
    _write(tmp_path, "src/C.java", _JAVA)
    _write(tmp_path, "lib/bc-fips-1.0.2.3.jar", "")
    _write(tmp_path, "lib/bcprov-jdk18on-1.80.jar", "")
    f = crypto.scan_java(tmp_path)
    ids = _ids(f)
    assert [x.line for x in _by_id(f, "JC-002")] == [5]
    assert "JC-003" not in ids and "JC-001" not in ids  # OAEP is fine; DES only in a comment
    assert "JC-005" in ids
    assert {"JC-FIPS-001", "JC-FIPS-002", "JC-FIPS-004", "JC-FIPS-005", "JC-FIPS-006", "JC-INV-001"} <= set(ids)
    assert "JC-FIPS-008" not in ids  # bcprov 1.80 is past the CVE fixes


_JAVA_CONFIG = '''package a;
public final class Config {
    public static final String TRANSFORM = "AES/" + "ECB" + "/PKCS5Padding";
    public static final String KEY = "0123456789abcdef";
    public static final byte[] FIXED_IV = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    public static final int RSA_BITS = 1024;
    public static final String KS_PASS = "changeit";
}
'''

_JAVA_UTIL = '''package a;
public class Util {
    private final byte[] zeroIv = new byte[16];
    private final byte[] goodIv = new byte[12];
    private final SecureRandom rnd = new SecureRandom();
    Util() { rnd.nextBytes(goodIv); }
    private String transform() { return Config.TRANSFORM; }
    byte[] ecb(Key k, byte[] d) throws Exception {
        Cipher c = Cipher.getInstance(transform());
        c.init(1, k, new IvParameterSpec(zeroIv));
        return c.doFinal(d);
    }
    byte[] gcm(Key k, byte[] d, byte[] nonce) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
        c.init(1, k, new GCMParameterSpec(128, nonce));
        c.init(1, k, new GCMParameterSpec(128, goodIv));
        byte[] iv = new byte[12];
        rnd.nextBytes(iv);
        c.init(1, k, new GCMParameterSpec(128, iv));
        return c.doFinal(d);
    }
    KeyPair kp() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(Config.RSA_BITS);
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(256);
        return g.generateKeyPair();
    }
    SecretKeySpec key() { return new SecretKeySpec(Config.KEY.getBytes(), "AES"); }
}
'''

_JAVA_CALLER = '''package a;
public class Caller {
    private final Util util = new Util();
    void run(Key k, byte[] body, InputStream in) throws Exception {
        util.gcm(k, body, Config.FIXED_IV);
        char[] pw = Config.KS_PASS.toCharArray();
        KeyStore ks = KeyStore.getInstance("BCFKS");
        ks.load(in, pw);
    }
}
'''


def test_java_crypto_follows_constants_fields_helpers_and_call_sites(tmp_path):
    """The values reaching each sink live in another class / field / caller --
    regex on the sink line can't see any of them."""
    _write(tmp_path, "src/a/Config.java", _JAVA_CONFIG)
    _write(tmp_path, "src/a/Util.java", _JAVA_UTIL)
    _write(tmp_path, "src/a/Caller.java", _JAVA_CALLER)
    f = crypto.scan_java(tmp_path)
    util = [x for x in f if x.file.endswith("Util.java")]
    by = lambda cid: sorted(x.line for x in util if x.check_id == cid)  # noqa: E731
    assert by("JC-002") == [9]            # ECB via helper return -> Config.TRANSFORM (concatenated)
    assert by("JC-005") == [10, 15]       # zero IV field; nonce param from Caller's constant
    assert by("JC-009") == [24]           # RSA 1024 via constant; EC 256 stays quiet
    assert by("JC-006") == [29]           # key from Config.KEY.getBytes()
    nonce = next(x for x in util if x.check_id == "JC-005" and x.line == 15)
    assert "Caller.java:5" in nonce.description and "Config.FIXED_IV" in nonce.description
    jc013 = [x for x in f if x.check_id == "JC-013"]
    assert [(x.file.endswith("Caller.java"), x.line) for x in jc013] == [(True, 8)]


def test_java_unparseable_file_falls_back_to_line_rules(tmp_path):
    _write(tmp_path, "src/Broken.java", 'class B { void f( { Cipher.getInstance("DES/CBC/PKCS5Padding"); }\n')
    assert "JC-001" in _ids(crypto.scan_java(tmp_path))


def test_bc_fips_approved_only_via_system_property(tmp_path):
    _write(tmp_path, "src/C.java", "class C { Object p = new BouncyCastleFipsProvider(); }")
    _write(tmp_path, "run.sh", "java -Dorg.bouncycastle.fips.approved_only=true -jar app.jar\n")
    _write(tmp_path, "pom.xml", "<dependency><groupId>org.bouncycastle</groupId><artifactId>bc-fips</artifactId>"
                                "<version>2.0.0</version></dependency>")
    ids = _ids(crypto.scan_java(tmp_path))
    assert "JC-FIPS-001" not in ids and "JC-FIPS-006" not in ids


def test_php_keygen_rules(tmp_path):
    _write(tmp_path, "keygen.php", '''<?php
mt_srand(time());
$token = bin2hex(random_bytes(32));
$cfg = ["private_key_bits" => 1024];
$enc = openssl_encrypt($d, "aes-256-gcm", $key, 0, "0000000000000000", $tag);
$ok  = openssl_encrypt($d, "aes-256-gcm", $key, 0, $iv, $tag);
''')
    f = crypto.scan_php(tmp_path)
    assert "PHP-002" in _ids(f) and "PHP-003" in _ids(f)
    assert [x.line for x in _by_id(f, "PHP-005")] == [5]
    assert "PHP-001" not in _ids(f)  # random_bytes is fine


# ── Lambda ──────────────────────────────────────────────────────────────────

_LAMBDA = '''import json, os, subprocess, requests

def lambda_handler(event, context):
    print(event)
    body = json.loads(event["body"])
    target = body["host"]
    subprocess.run(["ping", "-c", "1", "localhost"])
    os.system("ping " + target)
    requests.get(body["url"], timeout=5)
    helper(body["name"])
    return {"statusCode": 200}

def helper(name):
    import sqlite3
    c = sqlite3.connect(":memory:")
    c.execute("SELECT * FROM t WHERE n = ?", (name,))
    c.execute(f"SELECT * FROM t WHERE n = '{name}'")
'''


def test_lambda_taint_and_entry_point(tmp_path):
    _write(tmp_path, "fn/handler.py", _LAMBDA)
    findings, eps = aws_lambda.scan_project(tmp_path)
    by = {(f.check_id, f.line): f for f in findings}
    assert ("LMB-007", 4) in by
    assert ("LMB-001", 8) in by and by[("LMB-001", 8)].severity == "high"
    assert ("LMB-001", 7) not in by  # argument list, no shell, no taint
    assert ("LMB-005", 9) in by
    assert ("LMB-004", 17) in by and by[("LMB-004", 17)].severity == "high"  # taint through helper()
    assert ("LMB-004", 16) not in by  # parameterized
    assert len(eps) == 1 and eps[0].kind == "LambdaHandler" and eps[0].source_end_line == 11


def test_python_detector_reports_lambda_without_manifest(tmp_path):
    _write(tmp_path, "handler.py", "def handler(event, context):\n    return 1\n")
    results = enumerate_target(tmp_path)
    assert any(r.language == "python" and r.framework == "aws_lambda" and r.entry_points for r in results)


# ── ISR mapping + report ────────────────────────────────────────────────────

def test_every_new_rule_id_has_an_owasp_isr_category():
    ids = set()
    for name in ("terraform", "iam_policy", "gitlab_ci", "shell", "crypto", "aws_lambda", "repo_files", "secrets"):
        text = (Path(__file__).parent.parent / "checks" / f"{name}.py").read_text(encoding="utf-8")
        ids |= set(re.findall(r'"((?:TF|POL|GL|SH|JC|PHP|LMB|REPO|SECRET)-[A-Z0-9-]*\d)"', text))
    assert len(ids) > 100
    missing = sorted(i for i in ids if isr_for(i) is None)
    assert missing == []


def test_enumerator_and_html_infrastructure_tab(tmp_path):
    _write(tmp_path, "main.tf", 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
    _write(tmp_path, ".gitlab-ci.yml", "plan:\n  script:\n    - terraform plan\n")
    results = enumerate_target(tmp_path)
    frameworks = {(r.language, r.framework) for r in results}
    assert {("infra", "terraform"), ("infra", "gitlab_ci"), ("infra", "repo_files")} <= frameworks
    page = render_html(results, tmp_path)
    assert 'id="tab-panel-infra"' in page and "OWASP Top 10 Infrastructure Security Risks" in page
    assert 'class="finding-isr"' in page and 'data-isr="ISR09"' in page
    # infra findings live in the Infrastructure tab, not the generic Findings tab
    findings_panel = page.split('id="tab-panel-findings"')[1].split('id="tab-panel-infra"')[0]
    assert "TF-S3-001" not in findings_panel
