#!/usr/bin/env python3
"""Produce a metadata-only, machine-readable CodeQL SARIF triage index.

Intentionally exclude query messages, code snippets, data values, and SARIF
attachments from logs. Full SARIF stays in the short-lived workflow artifact.
"""
import argparse
from collections import Counter
import json
from pathlib import Path


def _location(obj):
    physical = (obj or {}).get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    return {
        "path": artifact.get("uri", ""),
        "line": region.get("startLine", 0),
    }


def _severity(rule, result):
    props = (rule or {}).get("properties") or {}
    score = props.get("security-severity")
    try:
        value = float(score)
    except (TypeError, ValueError):
        value = None
    if value is not None:
        if value >= 9:
            return "critical"
        if value >= 7:
            return "high"
        if value >= 4:
            return "medium"
        return "low"
    level = result.get("level") or ((rule or {}).get("defaultConfiguration") or {}).get("level")
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "unknown")


def collect(path):
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("version") != "2.1.0" or not isinstance(doc.get("runs"), list):
        raise ValueError("Expected SARIF 2.1.0 with runs")
    findings = []
    for run in doc["runs"]:
        driver = ((run.get("tool") or {}).get("driver") or {})
        rules = {rule.get("id"): rule for rule in driver.get("rules", [])}
        # CodeQL SARIF commonly stores queries in tool.extensions, not driver.rules.
        for extension in ((run.get("tool") or {}).get("extensions") or []):
            rules.update({rule.get("id"): rule for rule in extension.get("rules", [])})
        tool = driver.get("name", "unknown")
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            positions = result.get("locations") or []
            sink = _location(positions[0]) if positions else {"path": "", "line": 0}
            first_flow = ((result.get("codeFlows") or [{}])[0].get("threadFlows") or [{}])[0]
            locations = first_flow.get("locations") or []
            flow = [_location(entry.get("location")) for entry in locations]
            findings.append({
                "tool": tool,
                "rule": rule_id,
                "severity": _severity(rules.get(rule_id), result),
                "path": sink["path"],
                "line": sink["line"],
                "flow_start": flow[0] if flow else None,
                "flow_end": flow[-1] if flow else None,
                "flow_steps": len(flow),
            })
    return findings


def build_report(folder):
    sarif_files = sorted(folder.glob("*.sarif"))
    if not sarif_files:
        raise ValueError("No SARIF files found: refusing an empty security evidence artifact")
    findings = []
    for path in sarif_files:
        findings.extend(collect(path))
    counts = Counter(f["severity"] for f in findings)
    rules = Counter(f["rule"] for f in findings)
    return {
        "schema": "kaori-codeql-triage-v1",
        "sarif_files": [p.name for p in sarif_files],
        "result_count": len(findings),
        "severity_counts": dict(sorted(counts.items())),
        "rule_counts": dict(sorted(rules.items())),
        "findings": sorted(findings, key=lambda f: (f["rule"], f["path"], f["line"])),
        "note": "SARIF results are per-run detections; they are not GitHub open/closed alert lifecycle states.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True, help="Directory with CodeQL .sarif files")
    parser.add_argument("--output", type=Path, required=True, help="Sanitized summary JSON path")
    args = parser.parse_args()
    report = build_report(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("SARIF_SUMMARY " + json.dumps({
        "result_count": report["result_count"],
        "severity_counts": report["severity_counts"],
        "rule_counts": report["rule_counts"],
    }, sort_keys=True))
    for finding in report["findings"]:
        print("SARIF_FINDING " + json.dumps(finding, sort_keys=True))


if __name__ == "__main__":
    main()
