"""AWS Lambda (Python) deep-dive. Handlers are reported as EntryPoints (kind
"LambdaHandler") rather than Routes -- the HTTP path/method, if any, lives in
API Gateway / function URL config (Terraform), not in the code. Findings
(LMB-xxx, SECRET-xxx) are project-wide and correlate to their handler card
in the Entry Points tab by line range. See checks/aws_lambda.py."""
from __future__ import annotations

from checks import aws_lambda
from core.base import BaseFrameworkAnalyzer
from core.models import Finding, Route, ScanResult
from core.registry import register
from core.rulescan import dedupe


@register("python", "aws_lambda")
class LambdaAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        return []

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings, _ = aws_lambda.scan_project(self.target_path)
        return dedupe(findings)

    def analyze(self) -> ScanResult:
        findings, entry_points = aws_lambda.scan_project(self.target_path)
        return ScanResult(
            language=self.language,
            framework=self.framework,
            findings=dedupe(findings),
            entry_points=entry_points,
            notes=[
                "Lambda handlers are listed under Entry Points. Taint tracking is intra-module only -- "
                "check helpers imported from other modules/layers by hand."
            ] if entry_points else [],
        )
