# infra -- infrastructure-as-code review

No routes. Every finding is project-wide and lands in the HTML report's
**Infrastructure** tab, grouped per artifact type, under an **OWASP Top 10
Infrastructure Security Risks (2024)** coverage table. Every rule maps to an
ISR category (`core/owasp_isr.py`), shown as a badge on each finding, as a
SARIF rule tag, and as `category` in JSON.

| framework    | what's scanned | checks module |
|--------------|----------------|---------------|
| `terraform`  | `.tf`, `.tfvars`, `.hcl` | `checks/terraform.py` (+ `checks/hcl.py` parser) |
| `gitlab_ci`  | `.gitlab-ci.yml`, `*.gitlab-ci.yml`, CI YAML under `.gitlab/` / `ci/` | `checks/gitlab_ci.py` |
| `iam_policy` | any `.json` / `.json.tpl` / `.tftpl` containing an IAM-shaped document (identity, bucket, key, queue, trust policies; nested in CloudFormation too) | `checks/iam_policy.py` |
| `shell`      | `.sh`/`.bash`/`.ksh`/`.zsh` + extension-less files with an sh shebang | `checks/shell.py` |
| `repo_files` | always when any of the above is present | `checks/repo_files.py` |

Hardcoded-secret rules (`checks/secrets.py`, SECRET-001..006) run over all of
them, plus Lambda, Java and PHP.

Nothing here needs a new dependency: HCL is read by a small brace/heredoc-
aware block parser (line-accurate), and GitLab CI is split into jobs by
indentation rather than loaded as YAML, so every finding points at the exact
line.

## Terraform (AWS)

Per-resource checks only see **literal values**. `acl = var.acl` isn't
resolved, so check variable defaults and `.tfvars` by hand when the setting
you care about is a variable.

| area | ids | what |
|---|---|---|
| S3 | TF-S3-001..009 | public canned ACL / AllUsers grants; no public access block (cross-referenced by `bucket = aws_s3_bucket.x.id` or matching name, account-level block honoured); PAB with any flag off; no SSE / versioning / access logging / TLS-enforcing bucket policy; CORS `*`; website hosting |
| network | TF-NET-001..007 | 0.0.0.0/0 or ::/0 ingress on all ports or admin/datastore ports (22, 3389, 3306, 5432, 6379, 9200, 27017, ...), other non-web ports (REVIEW); default SG with rules; ALB not dropping invalid headers; VPC without flow logs; subnets auto-assigning public IPs |
| compute | TF-EC2-001/002, TF-ENC-001 | IMDSv1 allowed (no `http_tokens = "required"`); public IP; unencrypted root/EBS volumes |
| data | TF-DB-001..009 | publicly accessible RDS/Redshift; storage not encrypted; no deletion protection; master password in state; auto minor upgrades off; default admin usernames; ElastiCache/OpenSearch encryption; Redis with no auth token |
| Lambda | TF-LMB-001..008 | deprecated runtime; secret-looking env vars; env without CMK; function URL `authorization_type = "NONE"`; `lambda_permission` to `*` or to a service with no `source_arn` (confused deputy); layer shared with `*` |
| API GW | TF-API-001/002, TF-LOG-006 | methods/routes with no authorizer (REVIEW); full request/response data tracing; stage without access logs |
| IAM | TF-IAM-001..005 + POL-xxx | policies on users; AdministratorAccess/PowerUser/IAMFullAccess/*FullAccess attachments; `aws_iam_access_key` (long-lived keys, plaintext in state without `pgp_key`); login profiles without `pgp_key`; weak password policy. **Every** policy Terraform defines (`jsonencode`, heredoc JSON, `data "aws_iam_policy_document"`, `inline_policy`, `assume_role_policy`, bucket/key/queue/topic policies) goes through the POL rules below |
| crypto/TLS | TF-KMS-001, TF-ENC-002, TF-TLS-001..003 | KMS rotation off; SNS/SQS unencrypted; CloudFront/ELB/API GW allowing TLS < 1.2 or plain HTTP; TLS verification disabled |
| logging | TF-LOG-001..008 | CloudTrail validation/multi-region/KMS; log groups without CMK; ALB/CloudFront/API access logs; account baseline with no GuardDuty / Config / Security Hub (only when the config manages account-level resources -- REVIEW) |
| secrets | TF-SEC-001..003, TF-VAR-001..003, TF-PROV-001/002 | literal SSM/Secrets Manager values; secret-ish SSM `String`; secrets passing through state; secret variables without `sensitive`, with literal defaults; outputs exposing secrets; static provider credentials; provider `insecure` |
| state | TF-STATE-001..004 | S3 backend without `encrypt`/locking; local backend; HTTP backend over http:// |
| supply chain | TF-SUP-001..004 | git modules without `?ref=` or pinned to a branch; registry modules without `version`; providers without version constraints; root modules without `.terraform.lock.hcl` |
| execution | TF-EXEC-001/002 | `local-exec`/`remote-exec` interpolating `${var.*}` into a shell command; `data "external"` (runs at **plan** time, so in MR pipelines) |
| assets | TF-ASSET-001 | taggable resources with no `tags` and no provider `default_tags` |

## IAM / resource policies (POL-xxx)

Same rules for `.json` files and for policies inside Terraform.

- **POL-001** `Action: "*"` on `Resource: "*"` (admin).
- **POL-002** `Action: "*"` on scoped resources, or `service:*` (high for iam/sts/kms/secretsmanager/organizations/lambda/ec2/s3 on `*`).
- **POL-003** write actions on `Resource: "*"`.
- **POL-004** privilege-escalation actions, matched with IAM wildcard semantics (so `iam:Put*` catches `iam:PutRolePolicy`): PassRole, CreatePolicyVersion, Attach*/Put*Policy, CreateAccessKey, UpdateAssumeRolePolicy, lambda:UpdateFunctionCode, ssm:SendCommand, sts:AssumeRole... High on `*`, medium REVIEW when scoped.
- **POL-005** `Principal: "*"` with no Condition (high), or with conditions that don't restrict the caller's identity (medium REVIEW).
- **POL-006** data/key reads on `*` (s3:GetObject, secretsmanager:GetSecretValue, kms:Decrypt, ssm:GetParameter*...).
- **POL-007** Allow + NotAction/NotResource.
- **POL-008** S3 bucket policy without a `aws:SecureTransport = false` Deny.
- **POL-009** OIDC trust (GitLab, GitHub, any `oidc-provider`) with no `sub` condition (high), a wildcard `sub` (medium), or no `aud` (low). This is the one to look at hardest when GitLab CI assumes an AWS role.
- **POL-010** cross-account AssumeRole without `sts:ExternalId` (REVIEW).
- **POL-011** missing `Version: 2012-10-17` (policy variables silently don't work).

## GitLab CI

`extends:`, `!reference` and included templates are **not** merged in, so a
job that inherits `when: manual` from a template is still flagged by
GL-TF-001 (marked REVIEW when the job uses `extends`).

- **GL-001** `CI_DEBUG_TRACE` / `CI_DEBUG_SERVICES` on (dumps every variable, masked ones included).
- **GL-002** commit message / MR title / description in a script; **GL-003** branch/tag names inside `eval` / `sh -c`.
- **GL-004** `CI_JOB_TOKEN` sent to a non-GitLab host. **GL-008** tokens in git remote URLs.
- **GL-005** dind on 2375 / TLS disabled. **GL-011** dind / privileged jobs.
- **GL-006** security-scanning jobs with `allow_failure: true`. **GL-012** no scanning at all in any CI file (info).
- **GL-007** static AWS keys without `id_tokens` (OIDC). **GL-013** Terraform runs but no visible cloud auth (check CI variables in the UI).
- **GL-INC-001/002/003** remote includes without `integrity:`, project includes without `ref:` or pinned to a branch, components on `@main`/`~latest`.
- **GL-IMG-001** images without a tag or on `:latest` (digest-pinned images are fine).
- **GL-TF-001** `terraform apply` with no `when: manual` (medium when the job also has no `rules:`/`only:`); **GL-TF-002** apply without `environment:`; **GL-TF-003** plan/state files saved as artifacts (low if `artifacts:access` is restricted).
- Every **SH-0xx** script rule below also runs over CI YAML.

## Shell

Rules shared with CI (`SCRIPT_RULES`):

- SH-001 curl/wget piped into a shell; SH-002 TLS verification off (`curl -k`, `GIT_SSL_NO_VERIFY`, `NODE_TLS_REJECT_UNAUTHORIZED=0`...); SH-003 `eval` of variables.
- SH-004 world-writable chmod; SH-005 `TF_LOG=TRACE/DEBUG`; SH-006 `terraform validate/plan ... || true`; SH-007 `-auto-approve`; SH-008 `-lock=false`.
- SH-009 secrets in `-var`; SH-010 `state pull` / `show -json` / `output -json`; SH-011 secrets on any command line (`-passout pass:`, `--password=`...); SH-015 secrets echoed; SH-016 env dumps; SH-017 `set -x` in scripts touching secrets/terraform.
- SH-012 weak openssl (RSA < 2048, DES/3DES/RC4/MD5, ECB, `-nosalt`); SH-013 `openssl enc` without `-pbkdf2`; SH-014 keys generated with no passphrase.

Standalone-script only: SH-020 no `set -e` (medium when the script wraps terraform -- the wrapper's exit code is just the last command's); SH-021 terraform piped (`| tee`) without `pipefail`; SH-022 `rm -rf $VAR/` without `${VAR:?}`; SH-023 fixed `/tmp` paths; SH-024 `read` of a password without `-s`; SH-025 key files created without `umask 077`/`chmod 600`.

## Sensitive files (repo_files)

REPO-001 `*.tfstate`; REPO-002 private keys / keystores (`.key`, `.p12`, `.pfx`, `.jks`, `.bcfks`, `id_rsa`, PEMs containing a private key); REPO-003 `.env` files (not `.env.example`); REPO-004 saved plans / `crash.log`; REPO-005 `.gitignore` not excluding state/plans/`.terraform`. When the target is a git checkout, tracked files are high and untracked ones medium/low.

## Still manual

- GitLab project/group settings: CI/CD variables (protected? masked? environment-scoped?), protected branches/tags, protected environments + approvers, which runners (shared? privileged?) pick up deploy jobs, "Allow access to this project with a CI_JOB_TOKEN" allow-list.
- Whether a variable's runtime value makes a resource public / unencrypted (only literals are evaluated).
- What actually lives in the state bucket and who can read it (`s3:GetObject` on the state bucket = every secret in the stack).
- Effective permissions: SCPs, permission boundaries, resource policies in other repos.
- Anything in `extends`/included CI templates and in remote modules.
