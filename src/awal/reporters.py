from __future__ import annotations

import csv
import io
import json

from .models import ScanReport


def render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "text":
        return render_text(report)
    if output_format == "json":
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
    if output_format == "csv":
        return render_csv(report)
    if output_format == "sarif":
        return render_sarif(report)
    raise ValueError(f"Unsupported format: {output_format}")


def render_text(report: ScanReport) -> str:
    if not report.findings:
        return f"AWAL PASS: README matches the repo surface\nTarget: {report.target}\nRisk score: 0"

    severity = report.summary["by_severity"]
    lines = [
        f"AWAL {report.status.upper()}: {len(report.findings)} issue(s)",
        f"Target: {report.target}",
        f"Risk score: {report.risk_score}",
        "Summary: "
        f"critical={severity['critical']} high={severity['high']} "
        f"medium={severity['medium']} low={severity['low']}",
        "",
    ]
    for finding in report.findings:
        lines.extend(
            [
                f"{finding.severity.upper()}  {finding.category}  {finding.file}:{finding.line}",
                finding.excerpt,
                f"Why: {finding.why_it_matters}",
                f"Fix: {finding.suggested_review}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def render_csv(report: ScanReport) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "severity",
            "category",
            "file",
            "line",
            "excerpt",
            "why_it_matters",
            "suggested_review",
            "rule_id",
        ],
    )
    writer.writeheader()
    for finding in report.findings:
        writer.writerow(finding.to_dict())
    return buffer.getvalue()


def render_sarif(report: ScanReport) -> str:
    rules = {}
    results = []
    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.category,
            "shortDescription": {"text": finding.category.replace("_", " ")},
            "fullDescription": {"text": finding.why_it_matters},
            "help": {"text": finding.suggested_review},
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": sarif_level(finding.severity),
                "message": {"text": f"{finding.excerpt}\n\n{finding.why_it_matters}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
            }
        )

    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Awal",
                            "informationUri": "https://github.com/mara-org/awal",
                            "rules": [rules[key] for key in sorted(rules)],
                        }
                    },
                    "results": results,
                }
            ],
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )


def sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
