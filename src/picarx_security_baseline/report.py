from __future__ import annotations

import json
from dataclasses import asdict
from typing import Iterable

from .checks import Finding


def render_json(findings: Iterable[Finding]) -> str:
    return json.dumps([asdict(finding) for finding in findings], indent=2)


def render_markdown(findings: Iterable[Finding]) -> str:
    rows = [
        "# PiCar-X Security Baseline Report",
        "",
        "| ID | Severity | Status | Finding | Evidence | Recommendation |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        rows.append(
            "| {check_id} | {severity} | {status} | {title} | {evidence} | {recommendation} |".format(
                check_id=escape_cell(finding.check_id),
                severity=escape_cell(finding.severity),
                status=escape_cell(finding.status),
                title=escape_cell(finding.title),
                evidence=escape_cell(finding.evidence),
                recommendation=escape_cell(finding.recommendation),
            )
        )
    rows.append("")
    return "\n".join(rows)


def escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
