"""GitLab CI/CD pipeline checks (GL-xxx, GL-TF-xxx, GL-IMG-xxx, GL-INC-xxx).

Line-accurate and dependency-free: jobs are split on column-0 keys rather
than by loading YAML (which would lose line numbers), and the shared shell
rules from checks/shell.py run over every line as well, since `script:`
entries are just shell.

Limitations worth remembering when reading the results:
  * `extends:` / `!reference` / `include:`d templates are not merged in --
    a job that inherits `when: manual` from a template will still be
    flagged by GL-TF-001. Those findings are marked REVIEW.
  * Project / group CI/CD variable settings (masked, protected, environment
    scope) and protected-branch rules live in the GitLab UI, not the repo.
    They decide whether most of these findings are exploitable -- check
    Settings > CI/CD > Variables and Settings > Repository > Protected
    branches by hand.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from checks import secrets, shell
from core.fsutil import _SKIP_DIRS, read_text_safe
from core.models import Finding
from core.rulescan import LineRule, make_finding, mask_comments, rel, scan_text

_RESERVED = {"stages", "variables", "include", "default", "workflow", "image", "services",
             "before_script", "after_script", "cache", "spec", "pages:deploy"}
_TOP_KEY = re.compile(r"^([^\s#\-][^:]*?):(?:\s|$)")
_TF_APPLY = re.compile(r"\b(?:terraform|tofu|terragrunt|gitlab-terraform)\s+(?:apply|destroy)\b")
_SCANNERS = re.compile(
    r"(?i)\b(?:SAST|Secret-Detection|IaC-SAST|Dependency-Scanning|Container-Scanning|"
    r"tfsec|checkov|trivy|kics|terrascan|tflint|gitleaks|trufflehog|semgrep|snyk|grype)\b"
)
_ATTACKER_TEXT_VARS = r"\$\{?(?:CI_COMMIT_MESSAGE|CI_COMMIT_TITLE|CI_COMMIT_DESCRIPTION|CI_MERGE_REQUEST_TITLE|" \
                      r"CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_AUTHOR)\b"
_ATTACKER_REF_VARS = r"\$\{?(?:CI_COMMIT_BRANCH|CI_COMMIT_REF_NAME|CI_COMMIT_REF_SLUG|CI_COMMIT_TAG|" \
                     r"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME)\b"


@dataclass
class Job:
    name: str
    start: int  # 1-based line of the job key
    end: int    # inclusive
    text: str   # masked text of the job body


def is_gitlab_ci_file(path: Path, text: str | None = None) -> bool:
    name = path.name.lower()
    if name.endswith((".gitlab-ci.yml", ".gitlab-ci.yaml")) or name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        return True
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    if ".gitlab" in path.parts or "gitlab" in name or "ci" in {p.lower() for p in path.parts[:-1]}:
        text = text if text is not None else read_text_safe(path)
        return bool(re.search(r"(?m)^\s+script:", text))
    text = text if text is not None else read_text_safe(path)
    return bool(re.search(r"(?m)^\s+script:", text) and re.search(r"(?m)^stages:|\$CI_|^\s+(?:rules|extends|stage):", text))


def iter_ci_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or any(p in _SKIP_DIRS for p in path.parts):
            continue
        if path.suffix.lower() in (".yml", ".yaml") and is_gitlab_ci_file(path):
            yield path


def split_jobs(masked: str) -> list[Job]:
    lines = masked.split("\n")
    starts: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = _TOP_KEY.match(line)
        if m:
            starts.append((i, m.group(1).strip().strip("'\"")))
    jobs = []
    for k, (i, name) in enumerate(starts):
        end = (starts[k + 1][0] - 1) if k + 1 < len(starts) else len(lines) - 1
        jobs.append(Job(name, i + 1, end + 1, "\n".join(lines[i:end + 1])))
    return jobs


def _line_in(job: Job, pattern: str) -> int:
    m = re.search(pattern, job.text, re.MULTILINE)
    return job.start + job.text.count("\n", 0, m.start()) if m else job.start


_GL_RULES: list[LineRule] = [
    LineRule("GL-001", "high", "CI debug tracing enabled",
             r"\bCI_DEBUG_(?:TRACE|SERVICES)\s*:\s*[\"']?(?:true|1)\b",
             "CI_DEBUG_TRACE prints every variable -- including masked and protected secrets -- to "
             "the job log, readable by anyone with access to job logs. Remove it."),
    LineRule("GL-002", "medium", "Attacker-controlled commit/MR text used in a script",
             _ATTACKER_TEXT_VARS,
             "Commit messages and MR titles/descriptions are free text from any contributor. Inside "
             "a script they can break out of quoting (`; curl ... | sh`, $(...)). Pass them through "
             "a file or an environment variable that is always double-quoted, never eval'd.",
             confidence="REVIEW"),
    LineRule("GL-003", "medium", "Branch/tag name interpolated into eval / sh -c",
             r"(?:\beval\b|\b(?:ba)?sh\s+-c\b)[^\n]*" + _ATTACKER_REF_VARS,
             "Git ref names can contain $, (, ), ; and backticks, so anyone who can push a branch can "
             "inject commands here.", confidence="REVIEW"),
    LineRule("GL-004", "medium", "CI_JOB_TOKEN sent to a non-GitLab host",
             r"\b(?:curl|wget|http)\b[^\n]*\$\{?CI_JOB_TOKEN\b",
             "The job token can read (and, depending on settings, write to) other projects. Make sure "
             "the request goes to $CI_API_V4_URL / $CI_SERVER_URL only.",
             exclude=r"CI_API_V4_URL|CI_SERVER_URL|CI_SERVER_HOST|CI_REGISTRY|gitlab",
             confidence="REVIEW"),
    LineRule("GL-005", "low", "Docker-in-Docker with TLS disabled",
             r"DOCKER_TLS_CERTDIR\s*:\s*[\"']{2}|DOCKER_HOST\s*:\s*[\"']?tcp://[^:]+:2375",
             "dind on 2375 without TLS exposes an unauthenticated Docker API to anything that can "
             "reach the service container (= root on the runner host for privileged runners)."),
    LineRule("GL-007", "low", "Static AWS keys used instead of OIDC",
             r"\$\{?AWS_SECRET_ACCESS_KEY\b|^\s*AWS_SECRET_ACCESS_KEY\s*:",
             "Long-lived keys in CI variables can be exfiltrated by any job that runs on a branch "
             "with access to them. Use GitLab id_tokens + AssumeRoleWithWebIdentity with a trust "
             "policy pinned to this project and protected refs.",
             file_suppress=r"\bid_tokens\s*:"),
    LineRule("GL-008", "low", "Token embedded in a git remote URL",
             r"https://[^\s/:@]*:\$\{?\w+\}?@",
             "Credentials in a URL end up in .git/config, process listings, and error messages. "
             "Use a credential helper or GIT_ASKPASS.", confidence="REVIEW"),
]


def _image_checks(masked: str, relative: str) -> list[Finding]:
    findings = []
    lines = masked.split("\n")
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(?:-\s+)?(?:image|name)\s*:\s*[\"']?([^\s\"'#]+)", line)
        services_item = re.match(r"^\s*-\s+[\"']?([\w.\-/]+(?::[\w.\-]+)?(?:@sha256:\w+)?)[\"']?\s*$", line)
        ref = None
        if m:
            key_is_name = re.match(r"^\s*(?:-\s+)?name\s*:", line)
            if key_is_name:
                prev = next((lines[j] for j in range(i - 1, -1, -1) if lines[j].strip()), "")
                if not re.search(r"^\s*(?:-\s+)?(?:image|services)\s*:\s*$|^\s*-\s*$", prev) and not re.match(r"^\s*-\s+name", line):
                    continue
                if re.match(r"^\s*-\s+name", line):
                    # `- name:` list item: only an image if inside services/image
                    up = next((lines[j] for j in range(i - 1, -1, -1)
                               if lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) < len(line) - len(line.lstrip())), "")
                    if not re.search(r"\bservices\s*:", up):
                        continue
            ref = m.group(2)
        elif services_item:
            up = next((lines[j] for j in range(i - 1, -1, -1)
                       if lines[j].strip() and not lines[j].lstrip().startswith("-")), "")
            if re.search(r"\bservices\s*:\s*$", up):
                ref = services_item.group(1)
        if not ref or "$" in ref:
            continue
        if "@sha256:" in ref:
            continue
        last = ref.rsplit("/", 1)[-1]
        if ":" not in last:
            findings.append(make_finding(
                "GL-IMG-001", "low", f"CI image without a tag: {ref}",
                "No tag means :latest -- the job silently runs whatever was pushed most recently. Pin "
                "a version tag, ideally plus @sha256 digest.", relative, i + 1))
        elif last.endswith(":latest"):
            findings.append(make_finding(
                "GL-IMG-001", "low", f"CI image pinned to :latest: {ref}",
                "Pin a version tag, ideally plus @sha256 digest, so a compromised or broken upstream "
                "image doesn't flow straight into the pipeline (which holds deploy credentials).",
                relative, i + 1))
    return findings


def _include_checks(masked: str, relative: str) -> list[Finding]:
    findings = []
    lines = masked.split("\n")
    in_include = False
    item: list[tuple[int, str]] = []

    def flush():
        if not item:
            return
        body = "\n".join(t for _, t in item)
        first_line = item[0][0]
        remote = re.search(r"remote\s*:\s*[\"']?(https?://\S+?)[\"']?\s*$", body, re.M) or \
            re.match(r"^\s*-\s*[\"']?(https?://\S+?)[\"']?\s*$", item[0][1])
        if remote and "integrity:" not in body:
            findings.append(make_finding(
                "GL-INC-001", "medium", f"Remote CI include without integrity check: {remote.group(1)}",
                "Whoever controls that URL controls this pipeline's jobs (and their secrets). Vendor "
                "the file into a project you control, or add `integrity: sha256-...`.",
                relative, first_line))
        if re.search(r"\bproject\s*:", body):
            ref = re.search(r"\bref\s*:\s*[\"']?([^\s\"']+)", body)
            if not ref:
                findings.append(make_finding(
                    "GL-INC-002", "medium", "Project CI include without ref",
                    "Without ref: the include tracks the other project's default branch -- anyone "
                    "who can merge there changes what this pipeline runs. Pin ref: to a tag or SHA.",
                    relative, first_line))
            elif not re.fullmatch(r"[0-9a-f]{40}|v?\d+(\.\d+)*", ref.group(1)):
                findings.append(make_finding(
                    "GL-INC-002", "low", f"Project CI include pinned to a branch ({ref.group(1)})",
                    "Pin ref: to a commit SHA or immutable tag.", relative, first_line, "REVIEW"))
        comp = re.search(r"\bcomponent\s*:\s*[\"']?(\S+?)@([^\s\"']+)", body)
        if comp and comp.group(2) in ("main", "master", "~latest", "HEAD"):
            findings.append(make_finding(
                "GL-INC-003", "medium", f"CI component pinned to {comp.group(2)}",
                "Pin the component to a released version or commit SHA.", relative, first_line))
        item.clear()

    for i, line in enumerate(lines, start=1):
        if re.match(r"^include\s*:", line):
            in_include = True
            inline = re.match(r"^include\s*:\s*[\"']?(https?://\S+?)[\"']?\s*$", line)
            if inline:
                item.append((i, "- " + inline.group(1)))
                flush()
            continue
        if in_include:
            if line and not line[0].isspace() and not line.startswith("-"):
                flush()
                in_include = False
                continue
            if re.match(r"^\s*-\s", line):
                flush()
            if line.strip():
                item.append((i, line))
    flush()
    return findings


def _job_checks(job: Job, relative: str) -> list[Finding]:
    findings = []
    if job.name in _RESERVED:
        return findings
    t = job.text
    if _TF_APPLY.search(t):
        manual = re.search(r"\bwhen\s*:\s*[\"']?manual\b", t)
        restricted = re.search(r"\b(?:rules|only)\s*:", t)
        env = re.search(r"\benvironment\s*:", t)
        if not manual:
            findings.append(make_finding(
                "GL-TF-001", "medium" if not restricted else "low",
                f"Job '{job.name}' applies Terraform without a manual gate",
                "terraform apply runs automatically"
                + (" on every pipeline (no rules:/only:)" if not restricted else "")
                + ". Use a manual job on the default/protected branch with a deployment `environment:` "
                "(protected environments add required approvers) and apply the saved, reviewed plan.",
                relative, _line_in(job, _TF_APPLY.pattern), "REVIEW" if "extends" in t else None))
        if not env:
            findings.append(make_finding(
                "GL-TF-002", "low", f"Job '{job.name}' applies Terraform without an environment",
                "Without `environment:` the job can't be a protected environment, so deploy approvals "
                "and environment-scoped (production-only) variables don't apply.",
                relative, job.start))
    art = re.search(r"\bartifacts\s*:", t)
    if art:
        plan_path = re.search(r"(?m)^\s*-\s*[\"']?[^\n]*(?:\.tfplan|tfplan|plan\.(?:cache|out|json|bin)|\.tfstate|\.terraform/)", t)
        report_plan = re.search(r"\bterraform\s*:\s*[\"']?[^\n]*plan", t)
        if plan_path or report_plan:
            restricted = re.search(r"\baccess\s*:\s*[\"']?(?:developer|maintainer|none)\b|\bpublic\s*:\s*false\b", t)
            expires = re.search(r"\bexpire_in\s*:", t)
            findings.append(make_finding(
                "GL-TF-003", "low" if restricted else "medium",
                f"Job '{job.name}' saves a Terraform plan/state as an artifact",
                "Plan files and state contain every sensitive value in plaintext (sensitive = true "
                "doesn't apply to the binary plan). "
                + ("" if restricted else "Anyone who can view the pipeline can download them -- set "
                   "artifacts:access: 'developer' (or encrypt the plan). ")
                + ("" if expires else "Also set a short expire_in."),
                relative, _line_in(job, r"\bartifacts\s*:")))
    if re.search(r"\ballow_failure\s*:\s*true\b", t) and _SCANNERS.search(job.name + "\n" + t):
        findings.append(make_finding(
            "GL-006", "low", f"Security scanning job '{job.name}' allowed to fail",
            "allow_failure: true means findings (or a broken scanner) never block a merge.",
            relative, _line_in(job, r"\ballow_failure\s*:")))
    if re.search(r"\bprivileged\s*:\s*true|docker:[\w.\-]*dind", t):
        findings.append(make_finding(
            "GL-011", "low", f"Job '{job.name}' uses Docker-in-Docker",
            "dind needs a privileged runner; a privileged container can take over the runner host "
            "and any other job's secrets on it. Prefer kaniko/buildah, or dedicated isolated runners.",
            relative, _line_in(job, r"privileged|dind"), "REVIEW"))
    return findings


def scan_file(path: Path, root: Path) -> list[Finding]:
    text = read_text_safe(path)
    relative = rel(path, root)
    masked = mask_comments(text, "hash")
    rules = _GL_RULES + shell.SCRIPT_RULES + secrets.secret_rules(bare_assignments=True)
    findings = scan_text(text, rules, relative, "hash")
    findings += _image_checks(masked, relative)
    findings += _include_checks(masked, relative)
    for job in split_jobs(masked):
        findings += _job_checks(job, relative)
    return findings


def scan_project(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    files = list(iter_ci_files(root))
    all_text = ""
    for path in files:
        findings.extend(scan_file(path, root))
        all_text += mask_comments(read_text_safe(path), "hash")
    main_ci = next((p for p in files if p.name in (".gitlab-ci.yml", ".gitlab-ci.yaml")), files[0] if files else None)
    if main_ci and not _SCANNERS.search(all_text):
        findings.append(make_finding(
            "GL-012", "info", "No security scanning in the pipeline",
            "No SAST / secret detection / IaC scanning (GitLab templates, tfsec, checkov, trivy, kics, "
            "gitleaks...) found in any CI file. Check whether it's enforced via a compliance "
            "pipeline or security policy instead; if not, add IaC + secret scanning.",
            rel(main_ci, root), 1, "REVIEW"))
    if main_ci and re.search(r"\bterraform\s+(?:plan|apply)", all_text) and not re.search(r"\bid_tokens\s*:", all_text) \
            and not re.search(r"AWS_SECRET_ACCESS_KEY|AWS_ROLE_ARN|ROLE_ARN", all_text):
        findings.append(make_finding(
            "GL-013", "info", "Cannot see how the pipeline authenticates to the cloud",
            "Terraform runs here but no id_tokens (OIDC) and no credential variables are referenced, "
            "so credentials come from project/group CI variables or the runner's instance role. "
            "Check Settings > CI/CD > Variables (protected + masked + environment-scoped?) and which "
            "runners can pick up these jobs.", rel(main_ci, root), 1, "REVIEW"))
    return findings
