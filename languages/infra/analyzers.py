"""One analyzer per infrastructure artifact type. None of these have routes:
every finding is project-wide and lands in the HTML report's Infrastructure
tab (see core/html_report.py), SARIF, JSON and --fail-on like any other."""
from __future__ import annotations

from checks import gitlab_ci, iam_policy, repo_files, shell, terraform
from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route
from core.registry import register
from core.rulescan import dedupe


class _FindingsOnly(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        return []

    def scan(self) -> list[Finding]:
        raise NotImplementedError

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        return dedupe(self.scan())


@register("infra", "terraform")
class TerraformAnalyzer(_FindingsOnly):
    def scan(self):
        return terraform.scan_project(self.target_path)


@register("infra", "gitlab_ci")
class GitlabCiAnalyzer(_FindingsOnly):
    def scan(self):
        return gitlab_ci.scan_project(self.target_path)


@register("infra", "iam_policy")
class IamPolicyAnalyzer(_FindingsOnly):
    def scan(self):
        return iam_policy.scan_policy_files(self.target_path)


@register("infra", "shell")
class ShellAnalyzer(_FindingsOnly):
    def scan(self):
        return shell.scan_project(self.target_path)


@register("infra", "repo_files")
class RepoFilesAnalyzer(_FindingsOnly):
    def scan(self):
        return repo_files.scan_project(self.target_path)
