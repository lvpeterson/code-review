"""Detection for infrastructure targets. "Framework" here is the kind of
infrastructure artifact -- each gets its own analyzer and report section:

  terraform   .tf / .tfvars / .hcl
  gitlab_ci   .gitlab-ci.yml and included CI YAML
  iam_policy  JSON files holding IAM-shaped policy documents
  shell       .sh/.bash scripts (or extension-less files with a sh shebang)
  repo_files  always, when any of the above is present: committed state
              files, private keys, plan files, .env
"""
from __future__ import annotations

from pathlib import Path

from checks import gitlab_ci, iam_policy, shell, terraform


def _any(it) -> bool:
    return next(iter(it), None) is not None


def detect_frameworks(target_path: Path) -> list[str]:
    found = []
    if _any(terraform.iter_tf_files(target_path)):
        found.append("terraform")
    if _any(gitlab_ci.iter_ci_files(target_path)):
        found.append("gitlab_ci")
    if iam_policy.has_policy_files(target_path):
        found.append("iam_policy")
    if _any(shell.iter_shell_files(target_path)):
        found.append("shell")
    if found:
        found.append("repo_files")
    return found


def detect_language(target_path: Path) -> bool:
    return bool(detect_frameworks(target_path))
