"""Finding construction for dotnet_legacy checks."""
from __future__ import annotations

from typing import Optional

from core.models import Finding, Route
from core.owasp_web import owasp_for


def dnl_finding(
    check_id: str,
    severity: str,
    title: str,
    description: str,
    file: str,
    line: int,
    *,
    route: Optional[Route] = None,
    api_surface: bool = False,
    confidence: Optional[str] = None,
) -> Finding:
    """Build a Finding tagged with OWASP Web 2025/2021 (+ API 2023 when it applies).

    `category` (the infrastructure ISR label) is deliberately left None.
    """
    return Finding(
        check_id=check_id,
        severity=severity,
        title=title,
        description=description,
        file=file,
        line=line,
        route=route,
        confidence=confidence,
        owasp=owasp_for(check_id, api_surface),
    )
