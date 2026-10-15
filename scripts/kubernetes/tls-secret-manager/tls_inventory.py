#!/usr/bin/env python3
"""Unified, read-only Kubernetes TLS discovery overview.

Joins the existing discovery inventory with declared Ingress TLS hosts.
Ingress hostnames are NOT DNS resolutions or live HTTPS/TLS verification.
No Kubernetes mutation, credential/key export, or certificate renewal occurs.
"""
import argparse
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

COLUMNS = (
    "namespace", "secret_name", "ingress_hostnames", "ingresses", "ingress_count",
    "expires_at_utc", "days_remaining", "status", "ingress_usage",
    "certificate_sans", "fingerprint_sha256",
)
CANDIDATE_COLUMNS = ("namespace", "secret_name", "mode", "reason")
STATUS_VALUES = ("VALID", "EXPIRING", "EXPIRED", "NOT_YET_VALID", "INVALID")


def _read_csv(path, required):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"Discovery CSV is missing or unsafe: {path}")
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or not set(required).issubset(reader.fieldnames):
            raise ValueError(f"Discovery CSV has missing columns: {path}")
        return list(reader)


def join_discovery(inventory_path, references_path):
    """One summary row per TLS Secret; keep all Ingress references and orphans."""
    inventory = _read_csv(
        inventory_path,
        ("namespace", "secret_name", "not_after", "days_remaining", "status",
         "ingress_count", "san", "fingerprint_sha256"),
    )
    references = _read_csv(
        references_path, ("namespace", "secret_name", "ingress", "host")
    )
    known = {}
    for item in inventory:
        identity = (item["namespace"].strip(), item["secret_name"].strip())
        if not all(identity) or identity in known:
            raise ValueError("Duplicate or invalid TLS Secret identity in discovery")
        if item["status"] not in STATUS_VALUES:
            raise ValueError(f"Unrecognized TLS status for {identity[0]}/{identity[1]}")
        known[identity] = item
    grouped = {key: [] for key in known}
    unresolved = []
    for ref in references:
        identity = (ref["namespace"].strip(), ref["secret_name"].strip())
        if not identity[0] or not (ref["ingress"].strip() and ref["host"].strip()):
            raise ValueError("Incomplete Ingress TLS reference in discovery")
        detail = {"namespace": identity[0],
                  "secret_name": identity[1] or "UNSPECIFIED_TLS_SECRET",
                  "ingress": ref["ingress"].strip(), "host": ref["host"].strip()}
        if identity in known:
            grouped[identity].append(detail)
        else:
            unresolved.append(detail)
    overview = []
    for key in sorted(known):
        obj = known[key]
        links = grouped[key]
        try:
            expected_count = int(obj["ingress_count"])
        except (ValueError, TypeError) as ex:
            raise ValueError(f"Invalid Ingress reference count for {key}") from ex
        if expected_count != len(links):
            raise ValueError(
                f"Ingress reference count changed/mismatched for {key[0]}/{key[1]}; "
                "rerun discovery before planning"
            )
        hosts = sorted({r["host"] for r in links})
        ingresses = sorted({r["ingress"] for r in links})
        overview.append({
            "namespace": key[0], "secret_name": key[1],
            "ingress_hostnames": "; ".join(hosts) if hosts else "NO_INGRESS_REFERENCE",
            "ingresses": "; ".join(ingresses),
            "ingress_count": expected_count,
            "expires_at_utc": obj["not_after"],
            "days_remaining": obj["days_remaining"], "status": obj["status"],
            "ingress_usage": "INGRESS_REFERENCED" if links else "NO_INGRESS_REFERENCE",
            "certificate_sans": obj["san"],
            "fingerprint_sha256": obj["fingerprint_sha256"],
        })
    return overview, sorted(unresolved, key=lambda r: (
        r["namespace"], r["secret_name"], r["ingress"], r["host"]
    ))


def summary(rows, unresolved=()):
    counts = {status: 0 for status in STATUS_VALUES}
    counts["NO_INGRESS_REFERENCE"] = 0
    for row in rows:
        counts[row["status"]] += 1
        if row["ingress_usage"] == "NO_INGRESS_REFERENCE":
            counts["NO_INGRESS_REFERENCE"] += 1
    counts["UNRESOLVED_INGRESS_REFERENCE"] = len(unresolved)
    counts["TLS_SECRETS"] = len(rows)
    counts["NAMESPACES"] = len({row["namespace"] for row in rows})
    return counts


def filter_overview(rows, *, namespace="", status="", query=""):
    if status and status not in STATUS_VALUES:
        raise ValueError("Unknown TLS status filter; choose a listed status")
    namespace, query = namespace.strip().lower(), query.strip().lower()
    return [
        row for row in rows
        if (not namespace or namespace in row["namespace"].lower())
        and (not status or row["status"] == status)
        and (not query or query in " ".join(
            (row["namespace"], row["secret_name"], row["ingress_hostnames"],
             row["ingresses"], row["certificate_sans"])).lower())
    ]


def candidates(rows, indices):
    """Generate only advisory targets; no plan or mutation is executed."""
    selected = []
    for i in sorted(set(indices)):
        if i < 1 or i > len(rows):
            raise ValueError("Candidate index is outside the filtered overview")
        row = rows[i - 1]
        if row["status"] in ("INVALID", "NOT_YET_VALID"):
            raise ValueError(f"Unsafe candidate {row['namespace']}/{row['secret_name']}: "
                             f"{row['status']}; correct and rediscover first")
        selected.append({
            "namespace": row["namespace"], "secret_name": row["secret_name"],
            "mode": "renew", "reason": "Discovery candidate only; approval and fresh plan required",
        })
    if not selected:
        raise ValueError("No TLS renewal candidates selected")
    return selected


def _safe_text(value):
    return str(value or "").replace("\r", " ").replace("\n", " ").replace("|", r"\|")


def render_markdown(rows, counts, unresolved, context, generated_at):
    lines = [
        "# Kubernetes TLS Discovery Overview",
        "",
        f"- Context: \`{_safe_text(context)}\`",
        f"- Report generated (UTC): {generated_at}",
        "- Scope: stored Kubernetes TLS Secret + configured Ingress TLS hosts only.",
        "- Ingress hostname is not proof of DNS resolution or live HTTPS certificate.",
        "- NO_INGRESS_REFERENCE does not prove a Secret is unused (Gateway/Pod/LB may consume it).",
        "",
        "## Summary",
        "",
        " | ".join(f"{key}: {value}" for key, value in counts.items()),
        "",
        "## TLS Secrets",
        "",
        "| Namespace | TLS Secret | Ingress hostname(s) | Expires (UTC) | Days | Status | Usage |",
        "| --- | --- | --- | --- | ---: | --- | --- |",
    ]
    for r in rows:
        lines.append("| " + " | ".join(_safe_text(r[key]) for key in (
            "namespace", "secret_name", "ingress_hostnames", "expires_at_utc",
            "days_remaining", "status", "ingress_usage",
        )) + " |")
    lines += ["", "## Unresolved Ingress TLS References", ""]
    if unresolved:
        lines += [
            "These references did not match a TLS Secret in the current discovery scope; "
            "they are not proof the named Secret is missing.",
            "",
            "| Namespace | Referenced Secret | Ingress | Hostname |",
            "| --- | --- | --- | --- |",
        ]
        lines.extend("| " + " | ".join(_safe_text(r[k]) for k in (
            "namespace", "secret_name", "ingress", "host",
        )) + " |" for r in unresolved)
    else:
        lines.append("None detected in the selected namespaces.")
    return "\n".join(lines) + "\n"


def _write_exclusive(path, data, *, as_csv=None):
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise ValueError(f"Refusing to overwrite existing or unsafe evidence: {path}")
    if as_csv is not None:
        with path.open("x", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=as_csv, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)
    else:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(data)
    path.chmod(0o600)
    return path


def write_overview_reports(report_dir, overview, unresolved, *, context="",
                           generated_at=None):
    """Persist metadata-only evidence without overwriting previous artifacts."""
    target = Path(report_dir).expanduser()
    if target.is_symlink() or not target.is_dir():
        raise ValueError("Evidence directory must already exist and must not be a symlink")
    generated_at = generated_at or datetime.now(timezone.utc).isoformat()
    counts = summary(overview, unresolved)
    json_report = {
        "schema_version": 1,
        "context": context,
        "report_generated_at_utc": generated_at,
        "source": "DISCOVERY_CSV_JOIN",
        "scope": "STORED_SECRET_AND_INGRESS_ONLY_NOT_LIVE_DNS_OR_HTTPS",
        "summary": counts, "secrets": overview,
        "unresolved_ingress_references": unresolved,
    }
    paths = {
        "csv": _write_exclusive(target / "tls-overview.csv", overview, as_csv=COLUMNS),
        "json": _write_exclusive(target / "tls-overview.json",
                                 json.dumps(json_report, indent=2, ensure_ascii=False) + "\n"),
        "markdown": _write_exclusive(
            target / "tls-overview.md",
            render_markdown(overview, counts, unresolved, context, generated_at)
        ),
    }
    return paths


def write_candidates(path, rows):
    return _write_exclusive(path, rows, as_csv=CANDIDATE_COLUMNS)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, help="Path to discovery inventory.csv")
    parser.add_argument("--ingress-references", required=True, help="Path to ingress-references.csv")
    parser.add_argument("--context", default="", help="Informational Kubernetes context label")
    parser.add_argument("--output-dir", required=True, help="Existing private output directory")
    parser.add_argument("--namespace", default="", help="Namespace substring filter")
    parser.add_argument("--status", default="", choices=("",) + STATUS_VALUES)
    parser.add_argument("--query", default="", help="Secret/host/SAN substring filter")
    args = parser.parse_args()
    try:
        rows, unresolved = join_discovery(args.inventory, args.ingress_references)
        filtered = filter_overview(rows, namespace=args.namespace, status=args.status,
                                   query=args.query)
        paths = write_overview_reports(args.output_dir, filtered, unresolved,
                                       context=args.context)
    except (ValueError, OSError) as ex:
        parser.exit(1, f"STOP: {ex}\n")
    print(json.dumps({"summary": summary(filtered, unresolved),
                      "evidence": {k: str(v) for k, v in paths.items()}}, indent=2))


if __name__ == "__main__":
    main()
