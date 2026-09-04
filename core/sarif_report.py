"""SARIF (Static Analysis Results Interchange Format) 2.1.0 export.

SARIF is the standard interchange format most static-analysis consumers
already understand -- GitHub Code Scanning (upload via `github/codeql-
action/upload-sarif`, surfaced as PR annotations and Security-tab alerts),
VS Code's SARIF Viewer extension (a proper triage UI: open in the Problems
panel, page through and mark each result), Azure DevOps, and others. This
tool's own HTML report is for browsing findings in context (route cards,
code snippets); a SARIF viewer's whole job is letting a reviewer work
through a flat list and mark each one off, so rather than reinventing that
workflow, findings are exported in a shape those tools already know how to
present that way.

By default every finding across the whole scan is included -- route-tied
ones (IDOR, VALID, MASS, SORT, XML) map onto SARIF just as naturally as the
project-wide ones, since SARIF's location model is just file+line either
way and has no separate concept of "route." That's the right default for
`write_sarif`'s CLI/CI use (e.g. a GitHub Code Scanning upload wants every
finding surfaced as a PR annotation, not a subset). `build_sarif(...,
route_none_only=True)` narrows to just the findings with no route --
that's what the HTML report's own "Download SARIF" button uses, since
route-tied findings already have a much richer native UI there (route
cards: code snippets, highlighting, IDE links, reviewed checkboxes) --
including them in a side-by-side SARIF viewer would just be re-triaging
the same finding twice in two different views.

Findings are grouped by check_id into SARIF "rules" (tool.driver.rules) --
every SARIF-aware viewer groups/filters by rule automatically, which is
what gives the "run through one category at a time" experience. Each
Finding becomes one SARIF "result" referencing its rule, carrying the
finding's own file:line as its location.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.models import Finding, ScanResult

_SEVERITY_TO_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "none"}


def _rule(check_id: str, sample: Finding) -> dict:
    # SARIF wants a relatively static per-rule description; Finding
    # instances carry per-occurrence detail (a resolved value, a specific
    # API name) in their own title/description instead. Seeding the rule's
    # text from whichever finding of this check_id happened to be first is
    # a reasonable approximation without needing a second, separate
    # "generic description per check_id" registry to maintain in parallel
    # with every checks/*.py module.
    return {
        "id": check_id,
        "shortDescription": {"text": sample.title},
        "fullDescription": {"text": sample.description},
        "defaultConfiguration": {"level": _SEVERITY_TO_SARIF_LEVEL.get(sample.severity, "warning")},
    }


def _result(finding: Finding) -> dict:
    return {
        "ruleId": finding.check_id,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {"text": f"{finding.title}\n\n{finding.description}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file.replace("\\", "/")},
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
    }


def build_sarif(results: list[ScanResult], route_none_only: bool = False) -> dict:
    all_findings = [f for r in results for f in r.findings]
    if route_none_only:
        all_findings = [f for f in all_findings if f.route is None]

    rules: dict[str, dict] = {}
    for finding in all_findings:
        rules.setdefault(finding.check_id, _rule(finding.check_id, finding))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "appsec-review",
                        "version": "0.1.0",
                        "rules": [rules[check_id] for check_id in sorted(rules)],
                    }
                },
                "results": [_result(f) for f in all_findings],
            }
        ],
    }


def write_sarif(results: list[ScanResult], out_path: Path) -> None:
    out_path.write_text(json.dumps(build_sarif(results), indent=2), encoding="utf-8")
