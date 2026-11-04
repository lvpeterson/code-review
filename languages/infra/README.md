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

### Variable resolution (`checks/tf_resolve.py`)

Before any rule runs, `var.*`, `local.*` and module inputs are replaced by
the value they resolve to, in Terraform's precedence order:

1. `.tfvars` in the module's directory (`terraform.tfvars` / `*.auto.tfvars`
   first, then other `*.tfvars`). A `.tfvars` in a folder with no `.tf` files
   (`envs/prod.tfvars`) applies to every root module.
2. The argument a calling `module "x" { source = "./modules/y" }` passes
   (local sources only), resolved in the caller's own context.
3. The variable's `default`.

It follows chains (a local built from a variable that a caller passes from
its own tfvars), `"${var.x}"` interpolation, refs inside lists/objects, and
`var.flag ? a : b`. When several tfvars/callers disagree, the first wins and
the rest are listed. Every finding that depended on a resolved value ends
with the chain, e.g.
`Value resolved: acl = var.acl resolves via var.acl = "public-read" (module.logs in main.tf:14) <- local.open = true <- var.allow_public = true (terraform.tfvars:1) [other values: false in default in variables.tf:2]`.

Not resolved (left as-is, so the rule stays quiet): function calls
(`lookup`, `try`, `coalesce`...), resource/data attributes, `count`/`for_each`
values, remote module sources, variables with no value anywhere.

### Project model (`checks/tf_graph.py`)

Built once per scan and shared with the policy-JSON, GitLab CI and Lambda
analyzers:

- **Role permissions**: every policy reaching each `aws_iam_role` (inline,
  `managed_policy_arns`, `aws_iam_role_policy`, `*_policy_attachment` with
  AWS-managed or customer policies; bodies from `jsonencode`, heredoc,
  `data "aws_iam_policy_document"`, `file()` and `templatefile()`),
  summarised as admin / privilege escalation / writes / data reads on `*`.
- **Policy files** loaded via `file()`/`templatefile()` -> the resources that
  use them; POL findings in the JSON say "Attached in Terraform via ...".
- **Lambda**: function -> execution role, handler source file (handler +
  `archive_file` source_dir/source_file), public triggers (URL with
  `NONE` auth, permission to `*`, API Gateway).
- **GitLab OIDC trust**: which project/refs each role's `sub` allows.

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
| GitLab OIDC | TF-OIDC-001/002 | role whose GitLab trust `sub` allows any branch/MR (or any project) -- **high when the role can write / is admin**, with the role's actual permissions in the finding; OIDC provider over `http://` or accepting any audience |
| containers / build | TF-ECS-001..003, TF-CB-001/002 | privileged ECS containers, secret-looking plaintext `environment`, host network/PID; privileged CodeBuild, PLAINTEXT secret env vars |
| more data stores | TF-ENC-003/004, TF-DB-010, TF-LOG-009 | unencrypted EFS / Kinesis / Firehose; DynamoDB without PITR; Step Functions logging off |
| edge | TF-NET-008 | internet-facing ALB / API stage / CloudFront with no WAF association (REVIEW) |
| sessions | TF-IAM-006 | role `max_session_duration` > 1h |

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

Job inheritance is merged before the job rules run (`checks/gitlab_merge.py`):
`extends:` (lists, multi-level), YAML anchors (`<<: *x`), `!reference`,
top-level `default:` (unless `inherit: default: false`) and `include: local:`
files. A job that gets `when: manual` + protected-branch `rules:` from a
template is therefore *not* flagged. Templates from `include:
project/remote/template/component` can't be read; findings that depend on
them are REVIEW and name the missing template.

- **GL-TF-004** -- terraform (`init`/`validate`/`plan`/`apply`, directly or
  through a repo script like `./scripts/plan.sh`) running with cloud
  credentials (`id_tokens`, AWS key variables, a role ARN) in pipelines for
  merge requests or any branch. Anyone who can push a branch controls the
  `.tf` files and scripts that job runs (`data "external"`, a malicious
  provider, local-exec), so it's code execution as the deploy identity.
  The job is matched to the IAM role it assumes (role ARN in the CI file,
  or the only GitLab-trusted role in the repo's Terraform): **high** when
  that role's trust accepts unprotected refs and it can write; **low** when
  the trust is pinned to specific refs (check they're protected). A
  `workflow:` restricted to protected refs suppresses it.

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

## Dependencies (opt-in, `--sca`)

`python main.py <target> --sca` runs [osv-scanner](https://google.github.io/osv-scanner/)
(must be on PATH) over every lockfile/manifest and reports each vulnerable
package as **SCA-001** (ISR01) in a "Vulnerable dependencies" section. By
default osv-scanner sends package names + versions to api.osv.dev; add
`--sca-offline` to download the databases and match locally if that's a
concern for the engagement.

## Still manual

- GitLab project/group settings: CI/CD variables (protected? masked? environment-scoped?), protected branches/tags, protected environments + approvers, which runners (shared? privileged?) pick up deploy jobs, "Allow access to this project with a CI_JOB_TOKEN" allow-list.
- Values set outside the repo (`-var` on the command line, `TF_VAR_*` CI variables, Terraform Cloud workspace variables) and values computed by functions -- the resolver only sees tfvars, module callers and defaults.
- What actually lives in the state bucket and who can read it (`s3:GetObject` on the state bucket = every secret in the stack).
- Effective permissions: SCPs, permission boundaries, resource policies in other repos.
- CI templates from other projects / remote URLs / the GitLab template catalog, and remote Terraform modules.
- Which GitLab branches/tags are actually protected (GL-TF-004 / TF-OIDC-001 tell you which refs matter).
