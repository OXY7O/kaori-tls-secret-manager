#!/usr/bin/env python3
"""Interactive, fail-closed Kubernetes TLS Secret renewal operator wizard."""
import argparse
import base64
import csv
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from tls_secret_manager import (
    Stop, check, covers, read_staged_targets, read_endpoint_targets,
    normalize_old_fp, plan_id,
)

HERE = Path(__file__).resolve().parent
WRAPPER = HERE / "tls-secret-manager.sh"
BRAND_LOGO_FILE = HERE.parents[2] / "assets" / "kaori-logo.png"


# ANSI is enabled only on an interactive color-capable terminal. Text labels
# always remain readable without color, Unicode, or third-party packages.
USE_COLOR = False
USE_ICONS = False
STATUS_GUIDE = {
    "SECRET_UPDATED_ENDPOINT_UNVERIFIED": (
        "Certificate updated but HTTPS verification has not passed", "execution-journal.json",
        "Inspect the live Secret and endpoint. Run verify-endpoints; do not repeat renewal."),
    "HOLD_IDENTITY_REVIEW": (
        "Target held because its certificate identity differs", "held-targets.csv",
        "Use Review HOLD to record fingerprint-bound approval, then create a fresh plan."),
    "HOLD_UNCHANGED_VERIFIED": (
        "HELD Secret still contains its original certificate", "held-targets.csv",
        "Investigate the HOLD reason and use the review menu; rollback is unnecessary."),
    "SKIPPED_ALREADY_CURRENT": (
        "Replacement certificate is already installed", "renewal-plan.csv",
        "No repeat update. Validate the application if needed."),
    "SKIPPED_ALREADY_CURRENT_VERIFIED": (
        "SKIPPED Secret retains the replacement certificate fingerprint", "renewal-plan.csv",
        "No new writes. Previous evidence is preserved."),
    "PARTIAL_ROLLBACK_ENDPOINT_UNVERIFIED": (
        "Selected target was restored", "execution-journal.json",
        "Verify the restored Secret and endpoint health."),
    "READY": ("Ready for renewal", "renewal-plan.csv", "Review all READY targets and obtain approval before renewal."),
    "HOLD": ("Certificate identity requires review", "held-targets.csv",
             "Secret unchanged. Check issuer, SAN, and certificate ownership, then open Review HOLD."),
    "SKIPPED": ("Replacement certificate already installed", "renewal-plan.csv",
                "No repeat update. Check application health separately if needed."),
    "BLOCKED": ("Safety requirements not met", "renewal-plan.csv",
                "Do not bypass. Resolve the controller, Ingress, or certificate issue and create a new plan."),
    "ENDPOINT_VERIFIED": ("HTTPS endpoint verified", "endpoint-verification.json",
                          "Check application health before closing the change."),
    "SECRET_VERIFIED_PENDING_ACTIVATION": (
        "Secret verified; application endpoint not yet activated", "endpoint-verification.json",
        "Perform HTTPS verification as a separate activation change when the hostname/Ingress is ready."),
    "COMPLETE_WITH_HELD_TARGETS": (
        "READY targets complete; some targets remain HELD", "held-targets.csv",
        "Use Review HOLD before creating a new batch."),
    "COMPLETE_WITH_HELD_AND_STAGED": (
        "HELD and staged targets remain", "renewal-report.csv",
        "Resolve HELD targets and staged Secret activation separately."),
    "COMPLETE_WITH_STAGED_SECRETS": (
        "Active targets complete; staged Secrets await activation", "renewal-report.csv",
        "Preserve evidence and verify staged HTTPS after activation."),
    "COMPLETE_ENDPOINT_VERIFIED": (
        "All updated targets passed HTTPS verification", "renewal-report.csv",
        "Validate application health and archive evidence."),
    "EXTERNAL_TLS_VERIFIED": (
        "Approved external TLS termination verified; Secret-bound HTTPS not asserted",
        "endpoint-verification.json",
        "Review independent NGINX/LB evidence and verify application/backend health."),
    "COMPLETE_WITH_EXTERNAL_TLS": (
        "External HTTPS TLS verified independently from Kubernetes Secret certificate",
        "endpoint-verification.json",
        "Complete application/Ingress/backend health UAT before acceptance."),
    "COMPLETE_ENDPOINT_UNVERIFIED": (
        "Kubernetes Secret updated; endpoint not yet verified", "execution-journal.json",
        "Inspect CA, SNI, LB/proxy, and fingerprints. Repeat verification only, not renewal."),
    "HOLD_DRIFT_REVIEW": ("HELD target changed independently; not written by this batch",
        "held-targets.csv", "Review the live Secret separately."),
    "SKIPPED_DRIFT_REVIEW": ("Previously installed Secret changed independently",
        "renewal-plan.csv", "Review the drift; do not replay renewal."),
    "STOPPED": ("Execution stopped or partially completed", "execution-journal.json",
                "Inspect resourceVersion and live Secret before recovery. Do not repeat renewal."),
    "ROLLED_BACK_ENDPOINT_UNVERIFIED": (
        "Full rollback completed; HTTPS endpoints still need verification",
        "execution-journal.json", "Verify each restored Secret and affected application."),
    "PARTIAL_ROLLBACK_UNCERTAIN": ("Recovery result is uncertain",
                                  "execution-journal.json",
                                  "STOP. Reconcile live cluster state; do not repeat rollback."),
}


def setup_display(plain=False):
    global USE_COLOR, USE_ICONS
    tty = sys.stdout.isatty()
    USE_COLOR = (tty and not plain and "NO_COLOR" not in os.environ
                 and os.environ.get("CLICOLOR") != "0"
                 and os.environ.get("TERM") != "dumb")
    USE_ICONS = tty and not plain and (sys.stdout.encoding or "").lower().startswith("utf")


def paint(text, color):
    return ("\033[" + str(color) + "m" + str(text) + "\033[0m") if USE_COLOR else str(text)


def icon(kind):
    unicode_icons = {
        "info": "ℹ️", "ok": "✅", "warn": "⚠️", "stop": "🛑",
        "next": "➜", "file": "📄", "lock": "🔒", "help": "💡", "step": "🔹",
    }
    ascii_icons = {
        "info": "[INFO]", "ok": "[OK]", "warn": "[WARN]", "stop": "[STOP]",
        "next": "->", "file": "[FILE]", "lock": "[SAFE]", "help": "[TIP]", "step": "[STEP]",
    }
    return unicode_icons[kind] if USE_ICONS else ascii_icons[kind]


def header(title):
    print("\n" + paint("=" * 70, 36))
    print(" " + paint(title, 1))
    print(paint("=" * 70, 36))



def _terminal_inline_png():
    """Display the distributed PNG only where an image protocol is confirmed.

    iTerm2 supports the OSC 1337 inline-image sequence. Other terminals get a
    compact representation of the same shield-K mark, not raw escape payloads.
    """
    if (not USE_COLOR or not sys.stdout.isatty()
            or os.environ.get("TERM_PROGRAM") != "iTerm.app"
            or os.environ.get("KAORI_NO_IMAGE") == "1"):
        return False
    try:
        data = BRAND_LOGO_FILE.read_bytes()
    except OSError:
        return False
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) > 256_000:
        return False
    encoded = base64.b64encode(data).decode("ascii")
    print("\033]1337;File=inline=1;width=66;preserveAspectRatio=1:"
          + encoded + "\a")
    return True


def brand_banner():
    """Render the KAORI shield-K identity with a PNG-capable TTY fallback."""
    width = shutil.get_terminal_size(fallback=(80, 24)).columns
    print()
    if _terminal_inline_png():
        return
    # Terminal rendition of assets/kaori-mark.png. No image viewer required.
    if width >= 43:
        shield = (
            "    .-----------.",
            "   /   _  __    \\",
            "  |   | |/ /     |",
            "  |   | ' /      |",
            "  |   | . \\      |",
            "  |   |_|\\_\\     |",
            "   \\             /",
            "    '-----------'",
        )
        for line in shield:
            print("  " + paint(line, 36))
    else:
        print("  " + paint("[K]", 36))
    print("  " + paint("KAORI TLS", 1))
    print("  " + paint("CERTIFICATE MANAGER", 1))
    print("  " + paint(("-" if not USE_ICONS else "─")
                       * max(12, min(44, width - 4)), 36))

def menu_entry(number, title, *, default=False, caution=False):
    """Color is supplementary: cyan inventory, yellow renewal, plain white otherwise."""
    line = f"  {number:>2}. {title}"
    style = 36 if default else 33 if caution else None
    print(paint(line, style) if style is not None else line)



def submenu_entry(number, title):
    """Unified, text-only submenu entry; actions stay explicit and numbered."""
    print(f"  {number:>2}. {title}")


def inventory_help():
    """Explain report boundaries without contacting Kubernetes."""
    header("INVENTORY HELP / READ ONLY")
    print("  1 Filter   Show only matching Secrets in this terminal view.")
    print("  2 Reset    Clear active filters; restore the full view.")
    print("  3 Export   Create an advisory CSV; NOT a renewal plan.")
    print("  0 Back     Return to the main menu without changing Secrets.")
    print()
    print("  INVENTORY REPORTS")
    print("  The full, unfiltered CSV, JSON and Markdown reports are already saved")
    print("  in the private discovery directory.")
    print("  Filtering never changes these original reports.")
    print()
    print("  INTERPRETATION")
    print("  Hostnames are configured Ingress references; they do not prove live")
    print("  DNS resolution, HTTPS trust, or endpoint health.")
    print("  A missing Ingress reference does not mean the Secret is unused.")
    print("  The renewal candidate CSV is advisory only, never an executable plan.")


def toolbox_help():
    """Read-only diagnostic choices; clarify on-host evidence side effects."""
    header("TLS TOOLBOX HELP / NO KUBERNETES WRITES")
    print("  1 Health        Expiry, key pair and Ingress SAN coverage")
    print("  2 Families      Compare certificate fingerprints and issuance")
    print("  3 Dependencies  Discover observed Ingress/Gateway/Pod consumers")
    print("  4 Doctor        Compare Secret with live HTTPS CA/SNI/fingerprint")
    print("  5 Metrics       Generate local Prometheus textfile evidence")
    print("  6 Reconcile     Inspect saved journal against current Secret state")
    print("  7 Multi-IP drift Probe DNS IPs and served HTTPS certificates")
    print("  Read-only means no Kubernetes Secret mutation; local reports may be saved.")
    print("  Gateway/LB/external consumers may not be fully discoverable.")


def renewal_help():
    """Pre-change operator guide only; does not authorize or start any operation."""
    header("RENEWAL GUIDE / APPROVAL REQUIRED")
    print("  1-3  Choose context/scope and discover candidate TLS Secrets")
    print("  4-5  Verify certificate/key and create a guarded renewal plan")
    print("  6    Map real HTTPS endpoints; staged Secrets require review")
    print("  7    Inspect READY/HOLD/SKIPPED and obtain authorization")
    print("  8-9  Encrypted backup, conditional update, verification/report")
    print("  Required: AUTHORIZED and the exact PLAN ID before any write.")
    print("  Multi-target/external TLS changes require an independent signature.")
    print("  No automatic retry or rollback; reconcile partial/unknown states.")
    print("  Use menu 1 for read-only inventory before menu 5 renewal.")


def show_operator_help():
    """Local-only operator reference: no kubectl, certificates or Secrets accessed."""
    header("HELP  /  TLS SECRET MANAGER")
    print("  PURPOSE")
    print("    Discover Kubernetes TLS Secrets, understand Ingress references,")
    print("    inspect certificate health, and execute guarded renewals.")
    print("    This is a terminal application, not a browser UI.\n")
    print("  MAIN MENU")
    for number, name, detail in (
        ("1", "Inventory", "Read-only Secret + Ingress overview; CSV/JSON/Markdown evidence."),
        ("2", "Expiry audit", "Read-only validity/expiry dates from stored TLS Secrets."),
        ("3", "Toolbox", "Read-only health, families, dependencies, TLS Doctor, drift and metrics."),
        ("4", "Reverify", "Recheck HTTPS from an existing renewal run; for a new test use Toolbox > TLS Doctor."),
        ("5", "Renew TLS", "Guided plan, authorized backup/write, verification and reporting."),
        ("6", "Review HOLD", "Review previously held targets; no Secret changes in review."),
        ("7", "History", "Inspect existing private run folders and journals."),
        ("8", "Status guide", "Detailed READY/HOLD/STOP and recovery status meanings."),
        ("9", "Help", "This reference page (also type ? or H)."),
        ("10", "Create TLS", "Guided preflight, signed approval and non-overwriting create."),
        ("11", "Delete TLS", "Guarded decommission with dependency audit and encrypted backup."),
        ("0", "Exit", "Leave the interactive menu."),
    ):
        print(f"    {number:>2}  {name:<13} {detail}")
    print("\n  LAUNCH / OPTIONS")
    print("    bash tls-secret-manager.sh                Open interactive menu")
    print("    bash tls-secret-manager.sh wizard --plain ASCII/no-color interface")
    print("    bash tls-secret-manager.sh wizard --help  Show wizard CLI options")
    print("    bash tls-secret-manager.sh --help         Show lower-level helper commands")
    print("    --context <name>       Starting kubectl context (still verified)")
    print("    --workspace <path>     Private evidence root, outside the repository")
    print("    --cert / --key <path>  Replacement PEM certificate and matching key")
    print("    --ca-bundle <path>     Custom trusted CA bundle")
    print("    --review-plan <path>   Review HOLD from saved renewal-plan.json")
    print("    --reviewed-holds <csv> Previously approved review-exception mapping")
    print("    --plain                Disable Unicode icons and ANSI colors")
    print("    Menu 10/11             Plan Create/Delete, then optional signed execution")
    renewal_help()
    print("\n  SAFETY / SHORTCUTS")
    print("    Menu 1 is the default and does not run renewal or rollback.")
    print("    Renewal needs a fresh plan, appropriate approval, encrypted backup,")
    print("    and explicit write authorization. Multi-target/external TLS changes")
    print("    require independent signed authorization; no automatic retry.")
    print("    Inventory hostnames are configured Ingress names, NOT live TLS proof.")
    print("    Reverify does not update Kubernetes Secrets but records local evidence.")
    print("    Use BACK to cancel a prompt; use 0 to exit a menu.")
    print("    Never commit PEM keys, kubeconfig or private discovery evidence.")
    ask("Press Enter to return to main menu", "")


def step(index, total, title, detail=None):
    """Stable text-first progress headings without decorative menu icons."""
    rule = "-" if not USE_ICONS else "─"
    print("\n  " + paint(rule * 48, 36))
    print("  " + paint(f"STEP {index}/{total}", 36) + f"  {title}")
    if detail:
        print(f"  Note: {detail}")


def hint(message):
    print(f"  {icon('help')} {message}")


def ok(message):
    print(f"{icon('ok')} {paint(message, 32)}")


def warning(message):
    print(f"{icon('warn')} {paint(message, 33)}")


def file_hint(name, path, reason=None):
    print(f"  {icon('file')} {name}: {path}")
    if reason:
        hint(reason)


def status_help(status, run_dir=None):
    description, filename, instruction = STATUS_GUIDE.get(
        status, ("Inspect run status and evidence", "execution-journal.json",
                 "Do not change the cluster until the status is understood."))
    label = paint(status, 33 if any(x in status for x in ("HOLD", "BLOCKED", "STOP", "UNCERTAIN")) else 36)
    print(f"\n{icon('info')} {label} — {description}")
    if run_dir:
        file_hint("Evidence file to inspect", Path(run_dir) / filename)
    else:
        file_hint("Evidence file to inspect", filename)
    hint(instruction)


def operator_error_message(message, run_dir=None):
    lowered = message.lower()
    warning("Operation stopped. No automatic recovery was attempted.")
    if "fingerprint mismatch" in lowered:
        hint("Endpoint certificate differs from the Secret. Compare replacement certificate, live Secret, and LB/proxy TLS termination.")
        if run_dir:
            file_hint("Endpoint mapping", Path(run_dir).parent.parent / "endpoints.csv")
    elif "resourceversion" in lowered or "drift" in lowered:
        hint("Cluster state has changed. Inspect execution-journal.json and live resourceVersion; do not repeat renewal.")
    elif "mapping" in lowered or "ingress" in lowered:
        hint("Inspect Ingress hostnames, endpoints.csv, and whether the Secret is intentionally pre-provisioned.")
    elif "kubectl" in lowered:
        hint("Inspect kubectl context, RBAC (get/list Secrets and Ingresses), and cluster API connectivity.")
    elif "ca" in lowered or "certificate" in lowered:
        hint("Inspect fullchain.pem, private key, SAN, CA chain, and certificate issuer.")
    if run_dir:
        for name in ("renewal-plan.csv", "held-targets.csv", "execution-journal.json"):
            path = Path(run_dir) / name
            if path.is_file():
                file_hint("Diagnostics", path)
    hint("If a journal already exists, use verify/report or the documented recovery procedure. Never replay renewal.")


def ask(question, default=None):
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{question}{suffix}: ").strip()
    if value.upper() == "BACK":
        raise Stop("Operator selected BACK; return to the main menu without replaying commands")
    return value or default or ""


def choose(label, values):
    check(bool(values), f"No available {label}")
    print(f"\n{label}")
    for i, v in enumerate(values, 1):
        print(f" {i:>2}. {v}")
    while True:
        val = ask("Select item number")
        if val.isdecimal() and 1 <= int(val) <= len(values):
            return values[int(val) - 1]
        print("Invalid selection; choose one of the displayed numbers.")


def exec_read(argv):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=60)
    check(p.returncode == 0, f"{argv[0]} read operation failed (exit {p.returncode})")
    return p.stdout


def helper(context, *args):
    argv = ["bash", str(WRAPPER)]
    if context:
        argv += ["--context", context]
    argv += list(map(str, args))
    # NEVER kill a mutating helper on an arbitrary clock timeout: it can leave a
    # successfully written Secret with an uncertain journal. Kubectl commands
    # inside the helper retain their own bounded request timeouts and checkpoints.
    write_operation = args and args[0] in ("renew", "rollback", "rollback-target")
    timeout = None if write_operation else 1200
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as ex:
        raise Stop(f"{args[0]} timed out; inspect evidence and cluster state, do not replay writes") from ex
    if p.stdout.strip():
        print(p.stdout.rstrip())
    if p.returncode != 0:
        # The helper emits sanitized STOP diagnostics, not raw certificate/private key material.
        raise Stop(p.stderr.strip() or f"Helper {args[0]} failed")
    return p.stdout


def csv_file(path, columns, rows):
    path = Path(path)
    check(not path.is_symlink() and not path.exists(), f"Refusing existing/unsafe file {path}")
    with path.open("x", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)
    path.chmod(0o600)


def run_path(output, token):
    check(token in output, f"Unable to parse helper output: {token}")
    directory = Path(output.rstrip().splitlines()[-1].split(token)[-1].strip())
    check(directory.is_dir(), f"Run directory missing: {directory}")
    return directory


def choose_indices(items):
    header("SELECT TLS SECRETS")
    hint("All listed Secrets are read-only at this stage. Select the approved targets.")
    for index, item in enumerate(items, 1):
        ns, secret = item["namespace"], item["secret_name"]
        validity = item["status"]
        color = 33 if validity in ("INVALID", "EXPIRED", "EXPIRING") else 32
        print(f"{index:>3}. {ns}/{secret}")
        print(f"     Status: {paint(validity, color)}  |  Ingress refs: {item['ingress_count']}")
        print(f"     SAN: {item['san'] or '-'}")
        print(f"     Expires at (UTC): {item.get('not_after') or '-'}")
        print(f"     Days remaining: {item.get('days_remaining') or ('0' if item.get('days_remaining') == '0' else '-')}")
        print(f"     Original fingerprint: {item['fingerprint_sha256'] or '-'}")
    hint("Enter comma-separated numbers, ALL, FIND keyword to search, or QUIT/BACK.")
    while True:
        answer = ask("Select Secret numbers / ALL / QUIT").upper()
        if answer == "QUIT":
            raise Stop("Cancelled: no Kubernetes changes performed")
        if answer.startswith("FIND "):
            keyword = answer[5:].strip().lower()
            check(bool(keyword), "Search keyword is required")
            found = [(i, row) for i, row in enumerate(items, 1)
                     if keyword in (row["namespace"] + "/" + row["secret_name"]).lower()]
            print(f"{icon('info')} Found {len(found)} Secret:")
            for i, row in found:
                print(f"   {i}. {row['namespace']}/{row['secret_name']} ({row['status']})")
            hint("Enter a matching item number to select it.")
            continue
        if answer == "ALL":
            check(ask("Type ALL to confirm selecting every listed Secret") == "ALL",
                  "ALL selection cancelled")
            return items
        parts = [p.strip() for p in answer.split(",") if p.strip()]
        if parts and all(p.isdecimal() and 1 <= int(p) <= len(items) for p in parts):
            chosen = [items[int(i) - 1] for i in sorted({int(p) for p in parts})]
            print(f"{icon('info')} {len(chosen)} Secrets selected:")
            for row in chosen:
                print(f"    {row['namespace']}/{row['secret_name']}")
            if ask("Confirm selection: type YES / no", "no") == "YES":
                return chosen
        warning("Invalid or unconfirmed choice. Example: 1,3,5.")


def inventory_section(title):
    """Readable, compact sections without changing text-only/ANSI behavior."""
    print()
    print("  " + paint(title, 36))
    print("  " + "-" * len(title))


def display_tls_overview(rows, unresolved, *, title="UNIFIED TLS DISCOVERY",
                         max_rows=30, context="", total_rows=None, filters=None):
    """Readable, responsive inventory preview; exports always keep complete data."""
    import shutil
    import textwrap
    import tls_inventory

    summary = tls_inventory.summary(rows, unresolved)
    width = shutil.get_terminal_size((120, 25)).columns
    total = len(rows) if total_rows is None else total_rows
    displayed = min(len(rows), max_rows)

    header(title)
    inventory_section("SCOPE")
    print(f"  {icon('lock')} READ ONLY   |   Context: {context or 'see source run'}")

    inventory_section("SUMMARY")
    print(f"  TLS Secrets: {summary['TLS_SECRETS']}    "
          f"Namespaces: {summary['NAMESPACES']}")
    print(f"  VALID: {summary['VALID']}    EXPIRING: {summary['EXPIRING']}    "
          f"EXPIRED: {summary['EXPIRED']}")
    print(f"  INVALID: {summary['INVALID']}    "
          f"NOT_YET_VALID: {summary['NOT_YET_VALID']}")
    print(f"  Without Ingress reference: {summary['NO_INGRESS_REFERENCE']}")
    print("  Unresolved Ingress TLS references (full discovery): "
          f"{summary['UNRESOLVED_INGRESS_REFERENCE']}")

    inventory_section("DISCOVERY NOTES")
    for note in (
        "Ingress hostnames are configured references, not proof of live DNS or HTTPS.",
        "A Secret without an Ingress reference may still be used by a Gateway, Pod, "
        "or external load balancer.",
    ):
        print(textwrap.fill(note, width=max(28, min(width - 2, 100)),
                            initial_indent="  - ", subsequent_indent="    "))

    inventory_section("RESULTS")
    if width >= 105:
        ns_width, secret_width = 20, 20
        host_width = min(34, width - 84)
        # Formatting requires exactly 84 + host_width visible columns.
        def shorten(value, limit):
            value = str(value) if value not in (None, "") else "-"
            return value if len(value) <= limit else value[:limit - 3] + "..."

        def render_line(number, namespace, secret, hosts, expires, days, status):
            return (f"  {number:>2}  {namespace:<{ns_width}}  "
                    f"{secret:<{secret_width}}  {hosts:<{host_width}}  "
                    f"{expires:<10}  {days:>5}  {status}")

        print(render_line("#", "Namespace", "TLS Secret",
                          "Ingress hostname(s)", "Expires UTC", "Days", "Status"))
        print("  " + "-" * (82 + host_width))
        for index, item in enumerate(rows[:max_rows], 1):
            status = item["status"]
            color = 31 if status in ("INVALID", "EXPIRED") else (
                33 if status in ("EXPIRING", "NOT_YET_VALID") else 32)
            print(render_line(str(index),
                              shorten(item["namespace"], ns_width),
                              shorten(item["secret_name"], secret_width),
                              shorten(item["ingress_hostnames"], host_width),
                              str(item.get("expires_at_utc") or "-")[:10],
                              str(item.get("days_remaining") if item.get(
                                  "days_remaining") not in ("", None) else "-"),
                              paint(status, color)))
    else:
        for index, item in enumerate(rows[:max_rows], 1):
            status = item["status"]
            color = 31 if status in ("INVALID", "EXPIRED") else (
                33 if status in ("EXPIRING", "NOT_YET_VALID") else 32)
            print(f"  {index}. {item['namespace']}/{item['secret_name']} "
                  f"[{paint(status, color)}]")
            print(f"     Ingress: {item['ingress_hostnames'] or '-'}")
            print(f"     Expires (UTC): {str(item.get('expires_at_utc') or '-')[:10]}"
                  f"    Days remaining: {item.get('days_remaining') if item.get('days_remaining') not in ('', None) else '-'}")
            print()

    if not rows:
        print("  No TLS Secrets match the current filters.")
    print(f"\n  Showing {displayed} of {total} TLS Secret(s).")
    if len(rows) > max_rows:
        hint(f"Showing first {max_rows}/{len(rows)} rows. "
             "CSV/JSON/Markdown include the FULL unfiltered overview.")

    if filters:
        inventory_section("ACTIVE FILTERS")
        for label, value in filters.items():
            if value:
                print(f"  {label:<12}: {value}")

    if unresolved:
        print()
        warning(f"{len(unresolved)} unresolved Ingress TLS reference(s) "
                "in the full discovery.")
        hint("See tls-overview.md for the original Ingress and hostname mappings.")
    return summary


def export_renewal_candidates(rows, output_dir):
    """Generate an advisory CSV only. A new live discovery and plan are mandatory."""
    import tls_inventory
    header("RENEWAL CANDIDATE EXPORT / READ ONLY")
    inventory_section("SCOPE")
    print("  Creates an advisory CSV from the displayed Inventory results.")
    print("  It does not create a renewal plan or change Kubernetes Secrets.")
    print("  Original full-inventory CSV, JSON and Markdown reports stay unchanged.")
    print("  Eligible: VALID, EXPIRING and EXPIRED. Investigate other states first.")
    inventory_section("AVAILABLE CANDIDATES")
    for i, row in enumerate(rows, 1):
        print(f"  {i:>3}. {row['namespace']}/{row['secret_name']} "
              f"[{row['status']}]")
        print(f"       Ingress: {row['ingress_hostnames'] or '-'}")
    inventory_section("SELECTION")
    raw = ask("Candidate numbers (1,3), ALL, or Enter to cancel", "")
    if not raw:
        hint("No candidate shortlist created.")
        return None
    if raw.upper() == "ALL":
        check(ask("Type ALL to confirm ALL displayed candidates") == "ALL",
              "Candidate selection not confirmed")
        indices = list(range(1, len(rows)+1))
    else:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        check(bool(parts) and all(p.isdecimal() for p in parts),
              "Choose valid comma-separated candidate numbers")
        indices = [int(p) for p in parts]
    selected = tls_inventory.candidates(rows, indices)
    inventory_section("REVIEW SELECTION")
    print(f"  Selected candidates: {len(selected)}")
    for candidate in selected:
        print(f"  - {candidate['namespace']}/{candidate['secret_name']}")
    print()
    check(ask("Type CANDIDATES to export advisory targets only") == "CANDIDATES",
          "Candidate export not confirmed")
    destination = Path(output_dir) / "renewal-candidates.csv"
    tls_inventory.write_candidates(destination, selected)
    inventory_section("EXPORT COMPLETE")
    file_hint("Advisory candidates (no plan/no write)", destination)
    hint("Start main menu 5 (Renew TLS) separately; a FRESH discovery, plan and approval are required.")
    return destination


def tls_discovery_dashboard(args):
    """Standalone read-only UX; reuses the existing safe discover command."""
    import tls_inventory
    check(sys.stdin.isatty(), "Interactive TTY required")
    header("TLS INVENTORY / READ ONLY")
    hint("No certificate/key paths, backup credentials or renewal approval needed.")
    contexts = exec_read(["kubectl", "config", "get-contexts", "-o", "name"]).splitlines()
    context = args.context or choose("Select Kubernetes context", contexts)
    check(context in contexts, "Kubernetes context is not listed")
    ns_response = json.loads(exec_read(
        ["kubectl", "--context", context, "--request-timeout=20s",
         "get", "namespaces", "-o", "json"]
    ))
    namespaces = choose_namespaces(sorted(x["metadata"]["name"] for x in ns_response["items"]))
    raw_days = ask("Expiring warning threshold (days)", "30")
    check(raw_days.isdecimal() and 0 <= int(raw_days) <= 3650,
          "Warning threshold must be between 0 and 3650 days")
    root = Path(args.workspace).expanduser() if args.workspace else (
        Path.home() / "k8s-tls-private" / "wizard-runs"
    )
    check(not root.is_symlink(), "Evidence workspace must not be a symlink")
    root = root.resolve()
    check(root != HERE and HERE not in root.parents,
          "Evidence workspace must not be inside the script repository")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run = root / ("inventory-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                  + "-" + uuid.uuid4().hex[:8])
    run.mkdir(mode=0o700)
    allow_file = run / "namespaces.txt"
    allow_file.write_text("\n".join(namespaces) + "\n", encoding="utf-8")
    allow_file.chmod(0o600)
    output = helper(context, "discover", "--namespaces", allow_file,
                    "--runs-dir", run / "runs", "--warn-days", raw_days)
    report_dir = run_path(output, "reports: ")
    overview, unresolved = tls_inventory.join_discovery(
        report_dir / "inventory.csv", report_dir / "ingress-references.csv"
    )
    reports = tls_inventory.write_overview_reports(report_dir, overview, unresolved,
                                                    context=context)
    file_hint("Private discovery directory", report_dir)
    for kind, path in reports.items():
        file_hint(f"Unified overview {kind.upper()}", path)
    shown = overview
    active_filters = {}
    while True:
        display_tls_overview(shown, unresolved, context=context,
                             total_rows=len(overview), filters=active_filters)
        inventory_section("ACTIONS")
        submenu_entry("1", "Filter inventory")
        submenu_entry("2", "Reset filters")
        submenu_entry("3", "Export renewal candidates")
        submenu_entry("?", "Help")
        submenu_entry("0", "Back")
        print()
        choice = ask("Select action (? for Help)", "0").strip().upper()
        if choice in ("?", "H", "HELP"):
            inventory_help()
            continue
        if choice == "0":
            ok("Read-only TLS inventory complete. Kubernetes Secrets were not modified.")
            return report_dir
        if choice == "1":
            inventory_section("FILTER INVENTORY")
            namespace = ask("Namespace contains (Enter=all)", "")
            status = ask("Status: VALID, EXPIRING, EXPIRED, NOT_YET_VALID, INVALID (Enter=all)", "").upper()
            term = ask("Secret, hostname, Ingress or SAN contains (Enter=all)", "")
            try:
                filtered = tls_inventory.filter_overview(
                    overview, namespace=namespace, status=status, query=term
                )
            except ValueError as ex:
                warning(str(ex))
                continue
            shown = filtered
            active_filters = {
                "Namespace": namespace,
                "Status": status,
                "Search": term,
            } if any((namespace, status, term)) else {}
            if active_filters:
                ok(f"Filters applied. {len(shown)} matching Secret(s).")
            else:
                hint("No filters entered. Showing all TLS Secrets.")
        elif choice == "2":
            shown = overview
            active_filters = {}
            ok("Filters reset. Showing all TLS Secrets.")
        elif choice == "3":
            if not shown:
                warning("No candidates match the current filter. Reset or change filters.")
                continue
            try:
                export_renewal_candidates(shown, report_dir)
            except ValueError as ex:
                warning(str(ex))
        else:
            warning("Invalid inventory choice. Choose 0-3 or ? for Help.")


def print_validity_inventory(inventory, report_dir, threshold):
    """Present existing Secret leaf-certificate expiry; no HTTPS assertions."""
    header("TLS SECRET EXPIRATION AUDIT")
    hint(f"EXPIRING when the certificate has {threshold} days remaining or less.")
    hint("VALID here indicates only that the stored certificate has not expired.")
    hint("This does not establish tls.key matching, CA trust, or actual HTTPS served by an LB/Ingress.")
    colors = {"VALID": 32, "EXPIRING": 33, "EXPIRED": 31, "INVALID": 31}
    totals = {key: 0 for key in colors}
    for i, item in enumerate(inventory, 1):
        status = item.get("status", "INVALID")
        totals[status] = totals.get(status, 0) + 1
        target = f"{item['namespace']}/{item['secret_name']}"
        print(f"\n {i:>3}. {target}  {paint(status, colors.get(status, 31))}")
        print(f"      Expired at : {item.get('not_after') or 'UNREADABLE'}")
        print(f"      Days remaining  : {item.get('days_remaining') or ('0' if item.get('days_remaining') == '0' else '-')}")
        print(f"      SAN        : {item.get('san') or '-'}")
        print(f"      Ingress ref: {item.get('ingress_count') or '0'}")
        if status == "EXPIRING":
            hint(f"{target}: schedule renewal before expiration; verify certificate identity and ownership.")
        elif status == "EXPIRED":
            warning(f"{target}: stored certificate has expired; assess TLS impact and recovery priority.")
        elif status == "INVALID":
            warning(f"{target}: certificate could not be parsed; inspect the Secret using an approved procedure.")
    print("\n" + "  |  ".join(f"{state}: {totals.get(state, 0)}" for state in colors))
    file_hint("Full expiry inventory", report_dir / "inventory.csv")
    file_hint("Ingress references", report_dir / "ingress-references.csv")
    ok("Audit complete. No Secrets were modified.")
    hint("To renew, return to main menu 5 and create a new approved plan.")


def audit_secret_validity(args):
    """Operator-friendly certificate-expiration discovery only; never renews."""
    check(sys.stdin.isatty(), "Interactive TTY required")
    os.umask(0o077)
    header("TLS SECRET VALIDITY AUDIT • READ ONLY")
    print(f"{icon('lock')} This menu does not update, delete, or restart Secrets.")
    contexts = exec_read(["kubectl", "config", "get-contexts", "-o", "name"]).splitlines()
    context = args.context or choose("Select Kubernetes context for audit", contexts)
    check(context in contexts, "Kubernetes context not found.")
    ns_data = json.loads(exec_read([
        "kubectl", "--context", context, "--request-timeout=20s",
        "get", "namespaces", "-o", "json"
    ]))
    namespace_names = sorted(obj["metadata"]["name"] for obj in ns_data["items"])
    selected_namespaces = choose_namespaces(namespace_names)
    while True:
        days_input = ask("Expiring warning threshold (days)?", "30")
        if days_input.isdecimal() and 0 <= int(days_input) <= 3650:
            warning_days = int(days_input)
            break
        warning("Enter a number from 0 to 3650 days.")
    root = Path(args.workspace).expanduser() if args.workspace else (
        Path.home() / "k8s-tls-private" / "wizard-runs"
    )
    check(not root.is_symlink(), "The audit directory must not be a symbolic link.")
    root = root.resolve()
    check(HERE not in root.parents and root != HERE,
          "Evidence must not be stored inside the script repository.")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run = root / ("validity-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                  + "-" + uuid.uuid4().hex[:8])
    run.mkdir(mode=0o700)
    allow_file = run / "namespaces.txt"
    allow_file.write_text("\n".join(selected_namespaces) + "\n", encoding="utf-8")
    allow_file.chmod(0o600)
    output = helper(context, "discover",
                    "--namespaces", allow_file, "--runs-dir", run / "runs",
                    "--warn-days", str(warning_days))
    report_dir = run_path(output, "reports: ")
    with (report_dir / "inventory.csv").open(newline="", encoding="utf-8") as f:
        inventory = list(csv.DictReader(f))
    if not inventory:
        warning("No kubernetes.io/tls Secrets were found in the selected scope.")
        file_hint("Empty inventory evidence", report_dir / "inventory.csv")
        return
    print_validity_inventory(inventory, report_dir, warning_days)


def choose_baseline(selected, new_info):
    candidates = [r for r in selected
                  if set(filter(None, r["san"].split(";"))) == set(new_info["sans"])
                  and r["fingerprint_sha256"] != new_info["fingerprint"]]
    fingerprints = sorted({r["fingerprint_sha256"] for r in candidates})
    if not fingerprints:
        print("No distinct old certificate baseline is needed.")
        return None
    if len(fingerprints) == 1:
        print(f"\n{icon('info')} Only one original certificate fingerprint is a possible baseline:")
        print("  ", fingerprints[0])
        hint("Confirm this is the certificate family approved for this batch.")
        approved = ask("Type BASELINE to approve; any other response cancels")
        check(approved == "BASELINE", "Baseline not confirmed; stop before planning.")
        return fingerprints[0]
    warning("Multiple distinct original certificates share the same SAN.")
    hint("Do not choose by Secret count. Verify issuance and application ownership.")
    options = [
        f"{fp} ({sum(r['fingerprint_sha256'] == fp for r in candidates)} Secret(s))"
        for fp in fingerprints
    ] + ["HOLD: do not select a baseline; defer ambiguous certificate families"]
    choice = choose("Select the original fingerprint approved by the application owner", options)
    if choice.startswith("HOLD:"):
        return None
    fingerprint = choice.split(" ", 1)[0]
    check(ask("Type full selected 64-character fingerprint to confirm") == fingerprint,
          "Fingerprint confirmation mismatch; no changes performed.")
    return fingerprint


def build_endpoint_maps(plan, directory, staged_intents=None):
    endpoints, staged = [], []
    staged_intents = staged_intents or {}
    seen = set()
    header("TLS SECRET → DNS / INGRESS MAPPING")
    hint("ACTIVE requires a real HTTPS hostname for SNI, CA, and fingerprint validation.")
    hint("STAGED is only for unused pre-provisioned Secrets with documented approval.")
    hint("Never invent a hostname or change connect_host just to force PASS.")
    for e in plan["entries"]:
        if e["status"] != "READY":
            continue
        ns, secret = e["namespace"], e["secret_name"]
        print(f"\n{icon('next')} Secret READY: {ns}/{secret}")
        hosts = sorted({r["host"] for r in e.get("ingress_refs", [])})
        if not hosts:
            if (ns, secret) in staged_intents:
                staged.append({"namespace": ns, "secret_name": secret,
                               "reason": staged_intents[(ns, secret)]})
                ok(f"{ns}/{secret} was approved as STAGED before planning")
                continue
            warning("No Ingress references this Secret.")
            hint("It may be pre-provisioned OR consumed by another proxy/controller.")
            choice = ask("Type STAGED if not yet active, or ACTIVE if another real endpoint exists", "")
            check(choice in ("STAGED", "ACTIVE"), "Select STAGED or ACTIVE based on verified ownership; do not guess.")
            if choice == "STAGED":
                reason = ask("Staging reason / approval reference (at least 12 characters)")
                check(len(reason) >= 12, "Staging reason must be at least 12 characters")
                staged.append({"namespace": ns, "secret_name": secret, "reason": reason})
                ok(f"{ns}/{secret} marked PENDING_ACTIVATION; HTTPS has not been verified")
                continue
            hosts = [ask("Real HTTPS hostname (without https://)")]
            check(bool(hosts[0]), "A real hostname is required")
        for ingress in hosts:
            if "*" in ingress:
                hint(f"Ingress wildcard {ingress}; enter a concrete hostname actually used by the service.")
            else:
                print(f"  {icon('info')} Hostname Ingress: {ingress}")
            default_host = ingress if "*" not in ingress else None
            host = ask(f"HTTPS hostname for SNI ({ingress})", default_host)
            check(bool(host) and "*" not in host and "://" not in host,
                  "Enter a concrete hostname without wildcard or https://")
            check(covers(ingress, host),
                  f"Hostname {host} does not match the Ingress host {ingress}")
            port = ask("Port HTTPS", "443")
            check(port.isdecimal() and 1 <= int(port) <= 65535, "Port must be between 1 and 65535")
            hint("Connection address is optional. Leave it blank to connect via the SNI hostname;")
            hint("only override it to test a specific approved IP or load balancer.")
            hint("This step writes a local mapping file; certificate verification runs in Step 9.")
            destination = ask("Optional connection address (IP/hostname; Enter to use SNI hostname)", "")
            termination = ask("TLS termination: Enter=SECRET_BOUND, type EXTERNAL for approved NGINX/LB", "")
            check(termination in ("", "EXTERNAL"), "Choose Enter or EXTERNAL")
            mode = "EXTERNAL_TERMINATION" if termination == "EXTERNAL" else "SECRET_BOUND"
            expected_external, review_reason = "", ""
            if mode == "EXTERNAL_TERMINATION":
                warning("External HTTPS certificate is separate from the TLS Secret; review ownership.")
                expected_external = ask("Exact approved SHA256 of live NGINX/LB HTTPS leaf (64 hex)")
                check(bool(re.fullmatch(r"[0-9a-fA-F]{64}", expected_external)),
                      "Expected external SHA256 must contain 64 hexadecimal characters")
                review_reason = ask("Owner/change approval reference (minimum 16 characters)")
                check(len(review_reason) >= 16, "External termination requires owner approval evidence")
            identity = (ns, secret, host.lower())
            if identity in seen:
                continue
            seen.add(identity)
            endpoints.append({
                "namespace": ns, "secret_name": secret, "hostname": host,
                "port": port, "connect_host": destination,
                "verification_mode": mode,
                "expected_endpoint_fingerprint": expected_external.lower(),
                "review_reference": review_reason,
            })
    endpoint_file = directory / "endpoints.csv"
    csv_file(endpoint_file,
             ["namespace", "secret_name", "hostname", "port", "connect_host",
              "verification_mode", "expected_endpoint_fingerprint",
              "review_reference"], endpoints)
    staged_file = None
    if staged:
        staged_file = directory / "staged-targets.csv"
        csv_file(staged_file, ["namespace", "secret_name", "reason"], staged)
    accepted = read_staged_targets(staged_file, plan) if staged_file else {}
    read_endpoint_targets(endpoint_file, plan, accepted)
    ok(f"ENDPOINT MAPPING VALIDATED: {len(endpoints)} active endpoint(s), {len(staged)} staged Secret(s); HTTPS NOT YET TESTED")
    for endpoint in endpoints:
        destination = endpoint["connect_host"] or endpoint["hostname"]
        print(f"  {endpoint['hostname']}:{endpoint['port']} → connect to {destination}"
              f" (SNI: {endpoint['hostname']}; {endpoint['verification_mode']})")
        if endpoint["verification_mode"] == "EXTERNAL_TERMINATION":
            warning("External HTTPS is verified independently; it is not the Secret-bound endpoint.")
    hint("HTTPS hostname, trust chain and certificate fingerprint are verified in Step 9, after approved renewal.")
    return endpoint_file, staged_file


def review_hold_plan(args):
    """Read-only, interactive, fingerprint-pinned approvals for next safe batch."""
    os.umask(0o077)
    check(sys.stdin.isatty(), "Interactive terminal required to review held targets")
    plan_file = Path(args.review_plan).expanduser().resolve()
    plan = json.loads(plan_file.read_text())
    check(plan.get("schema_version") == 1 and plan_id(plan) == plan.get("plan_id"),
          "Old held plan integrity mismatch")
    held = [e for e in plan["entries"] if e["status"] == "HOLD"]
    check(held, "This plan has no HELD targets")
    header("REVIEW HELD SECRETS • NO KUBERNETES CHANGES")
    hint("Review records approval only; no Secrets are modified.")
    print("Original context:", plan["context"], "Plan ID:", plan["plan_id"])
    print("An old plan must not be replayed. This creates reviewed exceptions for a NEW plan.")
    approved = []
    for e in held:
        target = e["namespace"] + "/" + e["secret_name"]
        print("\nHOLD:", target)
        print("Reason:", e["message"])
        print("Original status:", e.get("base_status"))
        print("Old fingerprint:", e["old_fingerprint"])
        print("New fingerprint:", plan["new_fingerprint"])
        print("SAN:", ", ".join(e.get("old_sans", [])))
        comp = e.get("certificate_comparison") or {}
        print("Old Subject:", comp.get("old_subject") or "UNKNOWN")
        print("New Subject:", comp.get("new_subject") or "UNKNOWN")
        print("Old issuer:", comp.get("old_issuer") or "UNKNOWN")
        print("New issuer:", comp.get("new_issuer") or "UNKNOWN")
        print("Key rotated:", comp.get("public_key_match") is False)
        if e.get("base_status") != "READY":
            warning("HOLD was caused by a hard guardrail and cannot be overridden by approval alone.")
            hint("Inspect renewal-plan.csv, Ingress, cert-manager/ownerReferences, and certificate identity.")
            continue
        if ask("Owner and issuance reviewed? Type REVIEW to approve for a FUTURE plan") != "REVIEW":
            print("Remains on HOLD.")
            continue
        if ask("Type FULL 64-char old fingerprint to pin approval") != e["old_fingerprint"]:
            print("Fingerprint does not match; remains on HOLD.")
            continue
        reason = ask("Written approval reason, minimum 16 characters")
        check(len(reason) >= 16, "Reason too short; not approved")
        subject_only = (
            e.get("message") == "Identity review required: SUBJECT_CHANGED" and
            comp.get("subject_match") is False and
            comp.get("san_match") is True and
            comp.get("issuer_match") is True and
            bool(comp.get("old_subject")) and bool(comp.get("new_subject")) and
            bool(e.get("ingress_refs")) and
            e["old_fingerprint"] == (plan.get("selection_policy") or {}).get(
                "expected_old_fingerprint")
        )
        scope = "SUBJECT_ONLY" if subject_only else "IDENTITY"
        if subject_only:
            ok("Subject-only approval: cannot release issuer, SAN, or baseline mismatches.")
        approved.append({"context": plan["context"], "cluster_uid": plan["cluster_uid"],
                         "new_fingerprint": plan["new_fingerprint"],
                         "namespace": e["namespace"], "secret_name": e["secret_name"],
                         "old_fingerprint": e["old_fingerprint"], "reason": reason,
                         "approval_scope": scope,
                         "old_subject": comp.get("old_subject", "") if subject_only else "",
                         "new_subject": comp.get("new_subject", "") if subject_only else ""})
    check(approved, "No reviewed exceptions were approved; nothing written")
    root = Path(args.workspace).expanduser().resolve() if args.workspace else (
        Path.home() / "k8s-tls-private" / "wizard-runs"
    ).resolve()
    check(not root.is_symlink() and HERE not in root.parents and root != HERE,
          "Output workspace cannot be inside repository")
    root.mkdir(mode=0o700, exist_ok=True, parents=True)
    folder = root / ("held-review-" + uuid.uuid4().hex[:10])
    folder.mkdir(mode=0o700)
    output = folder / "reviewed-holds.csv"
    csv_file(output, ["context", "cluster_uid", "new_fingerprint",
                      "namespace", "secret_name", "old_fingerprint", "reason",
                      "approval_scope", "old_subject", "new_subject"], approved)
    ok("HOLD review saved; no Kubernetes changes performed.")
    file_hint("Approval review", output)
    hint("Create a NEW plan using this file. Already-updated Secrets will be SKIPPED.")
    return output


def choose_namespaces(all_ns):
    header("SELECT NAMESPACES")
    print("Namespaces discovered in the cluster:")
    for i, name in enumerate(all_ns, 1):
        print(f"  {i:>3}. {name}")
    hint("Enter item numbers (1,3,5), comma-separated namespace names, or ALL.")
    hint("ALL requires explicit confirmation because every namespace will be selected.")
    while True:
        text = ask("Namespaces to inspect").strip()
        if text.upper() == "ALL":
            check(ask("Type ALL to confirm including every namespace") == "ALL",
                  "All-namespace selection cancelled")
            return all_ns
        terms = [x.strip() for x in re.split(r"[\s,]+", text) if x.strip()]
        if not terms:
            warning("Select at least one namespace.")
            continue
        selected = []
        for term in terms:
            if term.isdecimal() and 1 <= int(term) <= len(all_ns):
                selected.append(all_ns[int(term)-1])
            elif term in all_ns:
                selected.append(term)
            else:
                warning(f"Unknown namespace: {term}")
                break
        else:
            names = sorted(set(selected))
            print(f"\n{icon('next')} Selected: {', '.join(names)}")
            if ask("Confirm selection: type YES / no", "no") == "YES":
                return names


def choose_certificate_inputs(args):
    header("REPLACEMENT CERTIFICATE FILES")
    default_cert = Path.home() / "k8s-tls-private/certs/fullchain.pem"
    default_key = Path.home() / "k8s-tls-private/certs/domain.key"
    hint("The certificate and private key must be on the workstation, never in Git.")
    hint("The private key is not printed or copied to wizard output.")
    cert_value = args.cert or ask("Path to new fullchain PEM",
                                  str(default_cert) if default_cert.is_file() else None)
    key_value = args.key or ask("Path to matching private key",
                                str(default_key) if default_key.is_file() else None)
    check(bool(cert_value) and bool(key_value), "Certificate and private key paths are required")
    cert, key = Path(cert_value).expanduser().resolve(), Path(key_value).expanduser().resolve()
    check(cert.is_file() and key.is_file(), "Certificate or key file not found; check the path.")
    if args.ca_bundle:
        ca_value = args.ca_bundle
    else:
        print("\nCA trust: system trust store is used by default for public CAs.")
        ca_value = ask("Path to internal root CA bundle (Enter for public CA)", "")
    ca = Path(ca_value).expanduser().resolve() if ca_value else None
    if ca:
        check(ca.is_file(), "CA bundle not found; check the path")
    return cert, key, ca


def prepare_staged_review(context, selected, new_info, workspace, previous_review=None):
    """Consent for pre-provisioned Secrets before plan; never auto-bypass identity."""
    candidates = [x for x in selected if int(x.get("ingress_count") or 0) == 0
                  and x.get("fingerprint_sha256") != new_info["fingerprint"]]
    if not candidates:
        return previous_review, {}
    header("REVIEW SECRETS WITHOUT INGRESS REFERENCES")
    hint("A Secret without Ingress references may be pre-provisioned, but is not necessarily unused.")
    hint("Verify application ownership, Gateway API, Pod mounts, proxies, and external controllers first.")
    hint("STAGED approval only releases a missing-Ingress HOLD, never other certificate identity mismatches.")
    approved_staged = {}
    for row in candidates:
        identity = (row["namespace"], row["secret_name"])
        print(f"\n{icon('warn')} {identity[0]}/{identity[1]}")
        print(f"  SAN: {row.get('san', '-')}")
        print(f"  Old fingerprint: {row['fingerprint_sha256']}")
        answer = ask("Type STAGED if truly not in use; otherwise leave on HOLD", "HOLD")
        if answer != "STAGED":
            continue
        check(ask("Enter the exact Secret name to confirm") == identity[1],
              "Pre-provisioned Secret confirmation does not match")
        reason = ask("Staged approval reason from application owner (at least 16 characters)")
        check(len(reason) >= 16, "Reason is too short")
        approved_staged[identity] = reason
    if not approved_staged:
        return previous_review, {}
    from tls_secret_manager import cluster_id
    cluster = cluster_id(context)
    fields = ["context", "cluster_uid", "new_fingerprint", "namespace",
              "secret_name", "old_fingerprint", "reason", "approval_scope",
              "old_subject", "new_subject"]
    merged = []
    if previous_review:
        with Path(previous_review).expanduser().open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            required = {"context", "cluster_uid", "new_fingerprint",
                        "namespace", "secret_name", "old_fingerprint", "reason"}
            check(reader.fieldnames and required.issubset(reader.fieldnames),
                  "Existing reviewed-holds.csv has unexpected schema")
            merged = [dict(row) for row in reader]
    for (ns, name), reason in approved_staged.items():
        row = next(x for x in selected if x["namespace"] == ns and x["secret_name"] == name)
        check(not any(x["namespace"] == ns and x["secret_name"] == name for x in merged),
              "Staged review duplicates existing held approval")
        merged.append({"context": context, "cluster_uid": cluster,
                       "new_fingerprint": new_info["fingerprint"],
                       "namespace": ns, "secret_name": name,
                       "old_fingerprint": row["fingerprint_sha256"],
                       "reason": reason, "approval_scope": "STAGED_ONLY",
                       "old_subject": "", "new_subject": ""})
    path = workspace / "preprovisioned-reviewed.csv"
    csv_file(path, fields, [{key: row.get(key, "") for key in fields}
                             for row in merged])
    file_hint("Fingerprint-pinned staged review", path)
    return str(path), approved_staged


def prepare_subject_review(context, selected, new_info, workspace,
                           baseline, previous_review=None):
    """Offer a non-writing review for Subject-only changes in an approved cert family.

    A Subject change never silently becomes READY. Approval is bound to the
    exact old/new certificate fingerprints, Subject strings, context and cluster.
    Issuer, SAN, no-Ingress, or baseline mismatch remain untouched by this scope.
    """
    candidates = []
    for row in selected:
        if (row.get("status") == "INVALID" or
            row.get("fingerprint_sha256") == new_info["fingerprint"] or
            row.get("fingerprint_sha256") != baseline or
            set(filter(None, row.get("san", "").split(";"))) != set(new_info["sans"]) or
            row.get("issuer", "") != new_info.get("issuer", "") or
            not row.get("subject") or not new_info.get("subject") or
            row["subject"] == new_info["subject"] or
            int(row.get("ingress_count") or 0) == 0):
            continue
        candidates.append(row)

    if not candidates:
        return previous_review

    header("CERTIFICATE SUBJECT CHANGE REVIEW (READ ONLY)")
    hint("The certificate Subject changed, but SAN, issuer and approved old fingerprint match.")
    hint("Changing the certificate fingerprint is expected during renewal.")
    hint("Public-key rotation alone is informational; certificate/key pairing is checked separately.")
    hint("Verify the application owner and intended certificate issuance before approving.")
    approved = []
    already_reviewed = set()
    if previous_review:
        with Path(previous_review).expanduser().open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            required = {"context", "cluster_uid", "new_fingerprint",
                        "namespace", "secret_name", "old_fingerprint", "reason"}
            check(reader.fieldnames and required.issubset(reader.fieldnames),
                  "Existing reviewed-holds.csv has unexpected schema")
            approved = [dict(row) for row in reader]
        already_reviewed = {(r["namespace"], r["secret_name"]) for r in approved}

    from tls_secret_manager import cluster_id
    for row in candidates:
        identity = (row["namespace"], row["secret_name"])
        if identity in already_reviewed:
            continue
        print(f"\n{icon('warn')} {identity[0]}/{identity[1]}")
        print("  Old Subject:", row["subject"])
        print("  New Subject:", new_info["subject"])
        print("  SANs       :", row["san"])
        print("  Issuer     :", row["issuer"])
        print("  Old SHA256 :", row["fingerprint_sha256"])
        print("  New SHA256 :", new_info["fingerprint"])
        hint("Decline to leave the Secret on HOLD. This review does not change Kubernetes.")
        if ask("Confirm the Subject change? Type SUBJECT to approve; Enter to HOLD", "") != "SUBJECT":
            warning("Subject change not approved. Secret will remain HOLD.")
            continue
        check(ask("Type the FULL original SHA256 fingerprint to pin approval") ==
              row["fingerprint_sha256"], "Subject review fingerprint confirmation mismatch")
        reason = ask("Approval reason / certificate ownership evidence (minimum 16 characters)")
        check(len(reason) >= 16, "Subject approval requires a meaningful reason (16+ characters)")
        approved.append({
            "context": context, "cluster_uid": cluster_id(context),
            "new_fingerprint": new_info["fingerprint"],
            "namespace": identity[0], "secret_name": identity[1],
            "old_fingerprint": row["fingerprint_sha256"], "reason": reason,
            "approval_scope": "SUBJECT_ONLY",
            "old_subject": row["subject"], "new_subject": new_info["subject"],
        })

    if not approved or len(approved) == len(already_reviewed):
        return previous_review
    fields = ["context", "cluster_uid", "new_fingerprint", "namespace",
              "secret_name", "old_fingerprint", "reason", "approval_scope",
              "old_subject", "new_subject"]
    path = workspace / "subject-reviewed.csv"
    csv_file(path, fields, [{key: row.get(key, "") for key in fields}
                            for row in approved])
    file_hint("Approved Subject changes for a NEW plan", path)
    return str(path)


def explain_plan(plan, plan_dir):
    entries = plan["entries"]
    counts = {state: sum(e["status"] == state for e in entries)
              for state in ("READY", "HOLD", "SKIPPED", "BLOCKED")}
    header("TARGET ASSESSMENT RESULTS")
    print("  " + "  |  ".join(
        f"{paint(key, 33 if key == 'HOLD' else 32 if key == 'READY' else 36)}: {count}"
        for key, count in counts.items()))
    print()
    for entry in entries:
        ns, name, state = entry["namespace"], entry["secret_name"], entry["status"]
        c = entry.get("certificate_comparison", {})
        color = 32 if state == "READY" else 33 if state == "HOLD" else 36
        print(f"  {paint(state.ljust(7), color)}  {ns}/{name}")
        print(f"           {entry['message']}")
        if c.get("flags"):
            print(f"           Notes: {', '.join(c['flags'])}")
    file_hint("Target summary", plan_dir / "renewal-plan.csv")
    file_hint("Certificate comparison", plan_dir / "certificate-comparison.csv")
    file_hint("Held targets", plan_dir / "held-targets.csv")
    file_hint("Complete plan (do not edit)", plan_dir / "renewal-plan.json")
    for state in ("HOLD", "SKIPPED", "BLOCKED"):
        if counts[state]:
            status_help(state, plan_dir)
    return counts


def show_run_status(plan_file):
    path = Path(plan_file).expanduser().resolve()
    check(path.is_file(), "renewal-plan.json was not found")
    plan = json.loads(path.read_text(encoding="utf-8"))
    check(plan.get("schema_version") == 1 and plan_id(plan) == plan.get("plan_id"),
          "Plan is invalid or has been modified")
    folder = path.parent
    header("RUN STATUS AND GUIDANCE")
    print("Cluster context:", plan.get("context"))
    print("Plan ID:", plan.get("plan_id"))
    print("Evidence directory:", folder)
    journal = folder / "execution-journal.json"
    if journal.is_file():
        data = json.loads(journal.read_text(encoding="utf-8"))
        current = data.get("status", "UNKNOWN")
        print("Execution status:", current)
        for item in data.get("items", []):
            print(f"  {item['namespace']}/{item['secret_name']} -> {item['status']}")
        status_help(current, folder)
    else:
        warning("No execution journal found: the plan has not been executed.")
        hint("If expired, create a NEW plan. Never construct a journal manually.")
    for entry in plan["entries"]:
        if entry["status"] in ("HOLD", "SKIPPED", "BLOCKED"):
            print(f"  {entry['status']}: {entry['namespace']}/{entry['secret_name']}")
    for name, meaning in (
        ("renewal-plan.csv", "Targets and initial statuses"),
        ("certificate-comparison.csv", "Original vs replacement certificate comparison"),
        ("held-targets.csv", "Held targets and reasons"),
        ("execution-journal.json", "Per-Secret post-execution status"),
        ("endpoint-verification.json", "Active/staged TLS validation evidence"),
        ("renewal-report.csv", "Final execution report"),
        ("backup/secrets.age", "Encrypted original backup (handle securely)"),
    ):
        if (folder / name).is_file():
            file_hint(meaning, folder / name)
    hint("This menu reads local files only; Kubernetes is not modified.")


def wizard(args):
    os.umask(0o077)
    check(sys.stdin.isatty(), "Interactive TTY required; no piped unattended renewal")
    root = Path(args.workspace).expanduser().resolve() if args.workspace else (
        Path.home() / "k8s-tls-private" / "wizard-runs"
    ).resolve()
    check(not root.is_symlink() and HERE not in root.parents and root != HERE,
          "Workspace must not be inside the script repository")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace = root / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") +
                        "-" + uuid.uuid4().hex[:8])
    workspace.mkdir(mode=0o700)
    args._workspace = workspace
    args._last_run_dir = None
    header("TLS RENEWAL / GUIDED CHANGE")
    print("  Discover > Plan > Authorize > Backup > Renew > Verify")
    warning("Use only in authorized DEV/UAT. Approval is required before a write.")
    print("  Already-current Secrets: SKIPPED  |  Identity mismatches: HOLD")
    file_hint("Private evidence directory", workspace)

    step(1, 9, "Select Kubernetes context", "No implicit Kubernetes context is used.")
    contexts = exec_read(["kubectl", "config", "get-contexts", "-o", "name"]).splitlines()
    context = args.context or choose("Select Kubernetes cluster/context", contexts)
    check(context in contexts, "Context not found; check kubectl config get-contexts")
    ok("Selected context: " + context)

    step(2, 9, "Select namespaces", "Select namespaces within the approved change scope.")
    ns_data = json.loads(exec_read([
        "kubectl", "--context", context, "--request-timeout=20s",
        "get", "namespaces", "-o", "json"]))
    all_ns = sorted(obj["metadata"]["name"] for obj in ns_data["items"])
    namespaces = choose_namespaces(all_ns)
    allow_file = workspace / "namespaces.txt"
    allow_file.write_text("\n".join(namespaces) + "\n", encoding="utf-8")
    allow_file.chmod(0o600)

    step(3, 9, "Discover TLS Secrets", "Read-only discovery; no resources are deleted.")
    discovered = helper(context, "discover", "--namespaces", allow_file,
                        "--runs-dir", workspace / "runs")
    report_dir = run_path(discovered, "reports: ")
    file_hint("Full inventory", report_dir / "inventory.csv")
    file_hint("Ingress → hostname mapping", report_dir / "ingress-references.csv")
    import tls_inventory
    overview, unresolved = tls_inventory.join_discovery(
        report_dir / "inventory.csv", report_dir / "ingress-references.csv"
    )
    reports = tls_inventory.write_overview_reports(report_dir, overview, unresolved,
                                                    context=context)
    display_tls_overview(overview, unresolved,
                         title="PRE-RENEWAL TLS INVENTORY (NO CHANGES)", context=context)
    for kind, path in reports.items():
        file_hint(f"Unified overview {kind.upper()}", path)
    with (report_dir / "inventory.csv").open(newline="", encoding="utf-8") as f:
        inventory = list(csv.DictReader(f))
    check(inventory, "No Kubernetes TLS Secrets found in the selected namespaces")
    selected = choose_indices(inventory)
    check(selected, "No Secrets selected")
    invalid = [r for r in selected if r["status"] == "INVALID"]
    check(not invalid, "An INVALID Secret was selected; review inventory.csv and exclude it from the batch.")

    step(4, 9, "Replacement certificate and original baseline",
         "A new fingerprint is expected; certificate ownership must still match.")
    cert, key, ca = choose_certificate_inputs(args)
    ca_args = ["--ca-bundle", ca] if ca else []
    source = helper(None, "verify-source", "--cert", cert, "--key", key, *ca_args)
    info = json.loads(source)
    ok("Source certificate and private key verified")
    print("  Replacement certificate SANs:", ", ".join(info["sans"]))
    print("  Fingerprint SHA256   :", info["fingerprint"])
    baseline = choose_baseline(selected, info)
    if not baseline:
        warning("With no approved baseline, ambiguous original certificate families will be HELD.")

    target_file = workspace / "targets.csv"
    csv_file(target_file, ["namespace", "secret_name", "mode", "reason"],
             [{"namespace": r["namespace"], "secret_name": r["secret_name"],
               "mode": "renew", "reason": ""} for r in selected])
    file_hint("Selected targets", target_file)

    step(5, 9, "Generate plan and classify targets", "READY proceeds; HOLD is deferred; SKIPPED is never rewritten.")
    plan_args = ["plan", "--namespaces", allow_file, "--targets", target_file,
                 "--cert", cert, "--key", key, *ca_args,
                 "--runs-dir", workspace / "runs"]
    if baseline:
        plan_args += ["--expected-old-fingerprint", baseline]
    reviewed_path = getattr(args, "reviewed_holds", None)
    if not reviewed_path:
        reviewed_path = ask("Previous reviewed-holds.csv path (Enter if none)", "")
    reviewed_path, staged_intents = prepare_staged_review(
        context, selected, info, workspace, reviewed_path or None)
    reviewed_path = prepare_subject_review(
        context, selected, info, workspace, baseline, reviewed_path)
    if reviewed_path:
        plan_args += ["--reviewed-holds", Path(reviewed_path).expanduser().resolve()]
    plan_output = helper(context, *plan_args)
    plan_dir = run_path(plan_output, " in ")
    args._last_run_dir = plan_dir
    plan_file = plan_dir / "renewal-plan.json"
    plan = json.loads(plan_file.read_text(encoding="utf-8"))
    counts = explain_plan(plan, plan_dir)
    if counts["BLOCKED"]:
        raise Stop("The plan contains BLOCKED targets; inspect renewal-plan.csv")
    if not counts["READY"]:
        warning("No READY Secrets found. Kubernetes remains unchanged.")
        if counts["HOLD"]:
            hint("Use main menu 6: Review HOLD (select the prior renewal-plan.json).")
        return

    step(6, 9, "Map HTTPS endpoints",
         "Real hostnames must match SNI/Ingress; staged Secrets require explicit justification.")
    endpoint_file, staged_file = build_endpoint_maps(plan, workspace, staged_intents=staged_intents)
    file_hint("Active endpoint mapping", endpoint_file)
    if staged_file:
        file_hint("Secrets pending activation", staged_file)

    step(7, 9, "Review and authorize changes", "No Kubernetes Secrets have been written up to this point.")
    with endpoint_file.open(newline="", encoding="utf-8") as stream:
        endpoints_for_approval = list(csv.DictReader(stream))
    requires_signature = counts['READY'] > 1 or any(
        row.get("verification_mode") == "EXTERNAL_TERMINATION"
        for row in endpoints_for_approval)
    signature_args = []
    if requires_signature:
        import hashlib
        warning("SIGNED APPROVER ATTESTATION REQUIRED: multi-Secret or external TLS write.")
        hint("Approval must be signed by a separate authorized approver using a trusted key.")
        request = {
            "schema_version": 1, "action": "RENEW", "target": "",
            "plan_id": plan["plan_id"],
            "context": context,
            "cluster_uid": plan["cluster_uid"],
            "endpoint_sha256": hashlib.sha256(endpoint_file.read_bytes()).hexdigest(),
            "staged_sha256": hashlib.sha256(staged_file.read_bytes()).hexdigest() if staged_file else "",
            "approved_utc": datetime.now(timezone.utc).isoformat(),
            "expires_utc": (datetime.now(timezone.utc) + timedelta(minutes=50)).isoformat(),
            "approver": "REPLACE_WITH_AUTHORIZED_APPROVER",
            "change_reference": "REPLACE_WITH_APPROVED_CHANGE_TICKET"
        }
        request_path = workspace / "approval-request.json"
        check(not request_path.exists(), "Refusing to overwrite existing approval request")
        request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
        request_path.chmod(0o600)
        file_hint("Approval request template (approver completes and signs)", request_path)
        hint("Sign the finalized JSON: openssl dgst -sha256 -sign approver.key -out approval.sig approval.json")
        hint("Install trusted approver public PEM as root-owned /etc/kaori/tls-approval-public.pem.")
        approver_record = Path(ask("Final signed approval JSON path")).expanduser()
        approver_signature = Path(ask("Detached signature path")).expanduser()
        approver_key = Path(ask("Trusted approver public PEM",
            "/etc/kaori/tls-approval-public.pem")).expanduser()
        check(approver_record.is_file() and approver_signature.is_file() and approver_key.is_file(),
              "Signed approval files are required before write")
        signature_args = [
            "--approval-record", approver_record,
            "--approval-signature", approver_signature,
            "--approval-trust-key", approver_key,
        ]
    print(f"\nCluster          : {context}")
    print(f"READY for renewal: {counts['READY']}")
    print(f"HELD, unchanged: {counts['HOLD']}")
    print(f"SKIPPED          : {counts['SKIPPED']}")
    print(f"Plan ID          : {plan['plan_id']}")
    created = datetime.fromisoformat(plan["created_utc"])
    minutes = round((timedelta(minutes=60) - (datetime.now(timezone.utc) - created)).total_seconds()/60, 1)
    print(f"Remaining plan validity   : ~{minutes} minutes")
    check(minutes > 0, "Plan expired; no write performed. Create a new plan.")
    warning("READY Secrets WILL BE REPLACED. Confirm change/UAT authorization.")
    check(ask("Type AUTHORIZED after approving scope, backup, and change") == "AUTHORIZED",
          "Operator cancelled execution. The plan remains saved.")
    check(ask("Type the exact PLAN ID to execute") == plan["plan_id"],
          "PLAN ID mismatch; operation cancelled.")
    check(timedelta(0) <= datetime.now(timezone.utc) - created < timedelta(minutes=60),
          "Plan expired before the write; create a new plan")

    recovery_default = str(Path.home() / ".config" / "age" / "k8s-tls-recovery.txt")
    recovery = Path(ask("Path to private age identity for encrypted backup",
                        recovery_default)).expanduser().resolve()
    check(recovery.is_file(), "Age identity not found; STOP before making changes")
    recipient = exec_read(["age-keygen", "-y", str(recovery)]).strip()
    check(recipient.startswith("age1"), "Invalid age recipient")

    step(8, 9, "Renew READY targets and verify stored Secrets", "Write only READY targets; save age-encrypted backups.")
    write_args = ["renew", "--namespaces", allow_file,
                  "--plan", plan_file, "--cert", cert, "--key", key,
                  "--endpoints", endpoint_file,
                  *ca_args, "--backup-recipient", recipient, "--approve", plan["plan_id"],
                  *signature_args]
    if staged_file:
        write_args += ["--staged-targets", staged_file]
    helper(context, *write_args)
    file_hint("Encrypted backup", plan_dir / "backup" / "secrets.age")
    file_hint("Execution journal", plan_dir / "execution-journal.json")
    ok("Renewal command completed. Continue stored Secret verification.")
    helper(context, "verify", "--plan", plan_file)

    step(9, 9, "Verify live HTTPS TLS and generate report",
         "Endpoint fingerprint must match the replacement certificate; mismatch = STOP.")
    verify_args = ["verify-endpoints", "--plan", plan_file, "--endpoints", endpoint_file]
    if staged_file:
        verify_args += ["--staged-targets", staged_file]
    if ca:
        verify_args += ["--ca-bundle", ca]
    verify_error = None
    try:
        helper(context, *verify_args)
    except Stop as err:
        verify_error = err
        operator_error_message(str(err), plan_dir)
    finally:
        try:
            helper(None, "report", "--plan", plan_file)
        except Stop as report_err:
            warning("Report could not be generated: " + str(report_err))
            file_hint("Journal remains available", plan_dir / "execution-journal.json")
    journal = json.loads((plan_dir / "execution-journal.json").read_text(encoding="utf-8"))
    status_help(journal["status"], plan_dir)
    file_hint("Renewal report", plan_dir / "renewal-report.csv")
    file_hint("TLS endpoint evidence (if PASS)", plan_dir / "endpoint-verification.json")
    if counts["HOLD"]:
        hint("HELD targets remain: use Review HOLD and create a NEW plan. Never replay this plan.")
    if counts["SKIPPED"]:
        hint("SKIPPED Secrets were not rewritten. Verify applications as needed.")
    if verify_error:
        raise Stop("Not all TLS endpoints are verified; inspect the errors and evidence above.")
    header("COMPLETION SUMMARY")
    ok("Wizard completed. Verify application health and archive the evidence.")
    print("Evidence:", plan_dir)


def recent_plans(args, held_only=False):
    """List prior wizard plans safely; no cluster/API calls or recursive filesystem sweep."""
    root = Path(args.workspace).expanduser().resolve() if args.workspace else (
        Path.home() / "k8s-tls-private" / "wizard-runs"
    ).resolve()
    if not root.is_dir():
        return []
    found = []
    for candidate in sorted(root.glob("*/runs/*/renewal-plan.json"),
                            key=lambda p: p.stat().st_mtime, reverse=True):
        if len(found) >= 20:
            break
        if candidate.is_symlink():
            continue
        try:
            plan = json.loads(candidate.read_text(encoding="utf-8"))
            if plan_id(plan) != plan.get("plan_id"):
                continue
            held_count = sum(e["status"] == "HOLD" for e in plan.get("entries", []))
            if held_only and not held_count:
                continue
            run_state = "NOT EXECUTED"
            journal_file = candidate.parent / "execution-journal.json"
            if journal_file.is_file() and not journal_file.is_symlink():
                run_state = json.loads(journal_file.read_text(encoding="utf-8")).get("status", "UNKNOWN")
            found.append((candidate, plan.get("context", "-"), held_count, run_state))
        except (OSError, ValueError, KeyError, TypeError):
            # Invalid historical local artifacts are never silently selected.
            continue
    return found


def choose_previous_plan(args, held_only=False, purpose="history"):
    """Allow optional manual plans, but make empty-history navigation easy to exit."""
    candidates = recent_plans(args, held_only=held_only)
    header("SELECT A PREVIOUS RUN")
    if candidates:
        print("  Select a saved run (up to 20 most recent):")
        for i, (path, context, held, state) in enumerate(candidates, 1):
            print(f"  {i:>2}. {path.parent.name} | context={context} | HOLD={held}")
            print(f"      Status: {state}")
        print()
        hint("You can also enter the full path to a saved renewal-plan.json.")
    else:
        warning("No matching saved renewal runs were found in this workspace.")
        if purpose == "reverify":
            hint("Main menu 5 > Renew TLS creates renewal-plan.json at Step 5/9.")
            hint("Reverify HTTPS needs that plan AND a journal from an executed renewal.")
            hint("A plan alone is not enough. Do not renew just to test HTTPS.")
            hint("For a first-time HTTPS check: Main menu 3 > TLS Toolbox > 4. TLS Doctor.")
        elif held_only:
            hint("Review HOLD requires a saved renewal plan with held targets.")
        else:
            hint("Run History shows saved renewal plans; use menu 5 to create a new plan.")
        hint("If a run was saved elsewhere, enter its full renewal-plan.json path.")
    print()
    print("  Press Enter or type 0/QUIT to return without making changes.")
    while True:
        prompt = ("Run number or renewal-plan.json path (Enter=Back)"
                  if candidates else "Full renewal-plan.json path (Enter=Back)")
        answer = ask(prompt, "").strip()
        if not answer or answer.upper() in ("0", "QUIT"):
            return None
        if answer.isdecimal() and 1 <= int(answer) <= len(candidates):
            return str(candidates[int(answer) - 1][0])
        path = Path(answer).expanduser()
        if path.is_file() and path.name == "renewal-plan.json":
            return str(path.resolve())
        if path.name == "results.json":
            warning("results.json is a diagnostic report, not a renewal-plan.json.")
            if purpose == "reverify":
                hint("TLS Doctor evidence cannot replace a saved renewal plan and journal.")
                hint("Menu 5 creates renewal-plan.json at Step 5/9; menu 4 requires an executed renewal.")
                hint("For a new HTTPS check use Main menu 3 > TLS Toolbox > 4. TLS Doctor.")
        else:
            warning("No valid renewal-plan.json found at that location.")
        if not candidates:
            hint("No saved runs are available here. Returning to the main menu.")
            return None
        hint("Select a listed run, enter a valid renewal-plan.json path, or press Enter to return.")


def toolkit_menu(args):
    """Read-only diagnosis center. Writes only local metadata evidence."""
    import tls_ops
    root = Path(args.workspace).expanduser() if args.workspace else (
        Path.home() / "k8s-tls-private" / "wizard-runs")
    root = root.resolve()
    check(HERE not in root.parents and HERE != root, "Reports may not be stored in repository")
    while True:
        header("TLS TOOLBOX  /  READ ONLY")
        submenu_entry("1", "Health")
        submenu_entry("2", "Certificate families")
        submenu_entry("3", "Dependencies")
        submenu_entry("4", "TLS Doctor")
        submenu_entry("5", "Metrics export")
        submenu_entry("6", "Journal reconciliation")
        submenu_entry("7", "Multi-IP drift")
        submenu_entry("?", "Help")
        submenu_entry("0", "Back")
        choice = ask("Tool (? for Help)", "0").strip().upper()
        if choice == "0":
            return
        if choice in ("?", "H", "HELP"):
            toolbox_help()
            ask("Press Enter to return to Toolbox", "")
            continue
        if choice not in "1234567" or len(choice) != 1:
            warning("Select a menu item from 0 to 7.")
            continue
        try:
            contexts = exec_read(["kubectl", "config", "get-contexts", "-o", "name"]).splitlines()
            context = args.context or choose("Select Kubernetes context", contexts)
            check(context in contexts, "Context not found")
            report_root = root / "toolkit-reports"
            if choice == "6":
                previous = choose_previous_plan(args)
                if previous:
                    result = tls_ops.check_run(context, previous)
                    saved = tls_ops.atomic_evidence(report_root, "run-reconcile", result)
                    for row in result["checks"]:
                        print(f"  {row['namespace']}/{row['secret_name']} -> {row['check']}")
                    file_hint("Reconciliation evidence", saved)
                    hint("No changes made. If UNKNOWN/DRIFT appears, never replay renewal.")
                continue
            ns_data = json.loads(exec_read(
                ["kubectl", "--context", context, "--request-timeout=20s",
                 "get", "namespaces", "-o", "json"]))
            all_ns = sorted(x["metadata"]["name"] for x in ns_data["items"])
            namespaces = choose_namespaces(all_ns)
            warn = ask("Expiration warning threshold (days)", "30")
            check(warn.isdecimal() and 0 <= int(warn) <= 3650, "Threshold must be 0–3650")
            rows = tls_ops.inventory(context, namespaces, int(warn))
            if not rows:
                warning("No kubernetes.io/tls Secrets found in the selected namespaces.")
                continue
            if choice == "1":
                print_validity_inventory([
                    {"namespace": r["namespace"], "secret_name": r["secret_name"],
                     "status": r["status"], "not_after": r["not_after"],
                     "days_remaining": r["days_remaining"], "san": r["san"],
                     "ingress_count": r.get("ingress_refs", 0)}
                    for r in rows], report_root, int(warn))
                for r in rows:
                    print(f"  HEALTH {r['namespace']}/{r['secret_name']}: "
                          f"tls.key={r['key_match']} trust={r['trust_status']} "
                          f"endpoint={r['endpoint_status']}")
                saved = tls_ops.atomic_evidence(report_root, "health",
                     {"context": context, "targets": rows,
                      "note": "Local Secret check; trust and HTTPS require separate probes."})
                file_hint("Full audit including key-pair checks", saved)
            elif choice == "2":
                family = tls_ops.analyze_families(rows)
                for group in family:
                    tag = "MIXED_FINGERPRINTS_REVIEW" if group["fingerprint_variants"] > 1 else "ONE_FINGERPRINT"
                    print(f"  {tag} SAN={group['san']} Secrets={group['secret_count']} "
                          f"certificate_variants={group['fingerprint_variants']}")
                saved = tls_ops.atomic_evidence(report_root, "families",
                    {"context": context, "families": family})
                file_hint("Certificate family details", saved)
                hint("Matching SANs do not prove common ownership/issuance. Review mixed fingerprints.")
            elif choice in ("3", "4"):
                selected = choose("Select TLS Secret", [
                    f"{r['namespace']}/{r['secret_name']}" for r in rows])
                ns, name = selected.split("/", 1)
                if choice == "3":
                    result = tls_ops.dependency_report(context, ns, name)
                    print(f"Detected consumers: {result['consumer_count']}")
                    print(f"Coverage: {result['check_coverage']}")
                    for consumer in result["known_consumers"]:
                        print(f"  - {consumer['kind']}/{consumer['name']}: {consumer['route']}")
                    hint(result["limitation"])
                    saved = tls_ops.atomic_evidence(report_root, "dependencies", result)
                else:
                    hostname = ask("HTTPS hostname to check (Enter to inspect Secret only)", "")
                    ca_path = ask("Internal CA bundle path (Enter for system trust)", "") if hostname else ""
                    result = tls_ops.doctor(context, ns, name, hostname or None,
                             ca_bundle=ca_path or None)
                    print("Stored:", result["stored"]["status"],
                          "| HTTPS:", result["endpoint"]["status"])
                    for item in result["diagnosis"]:
                        warning(item)
                    saved = tls_ops.atomic_evidence(report_root, "doctor", result)
                file_hint("Diagnostic evidence", saved)
            elif choice == "7":
                warning("Drift scan will establish HTTPS connections to each resolved Ingress IP.")
                max_ips = ask("Maximum IPs per hostname (1-16)", "4")
                check(max_ips.isdecimal() and 1 <= int(max_ips) <= 16,
                      "Invalid maximum IP count")
                bundle = ask("Internal CA bundle path (Enter for system trust)", "")
                result = tls_ops.drift_report(context, namespaces,
                          max_ips=int(max_ips), ca_bundle=bundle or None)
                for item in result["results"]:
                    label = item["namespace"] + "/" + item["secret_name"]
                    print(f"  {label} {item['hostname']} ({item['connect_ip']}): {item['status']}")
                saved = tls_ops.atomic_evidence(report_root, "drift", result)
                file_hint("Per-IP drift evidence", saved)
                hint("Legitimate external TLS termination may report MISMATCH; review before acting.")
            elif choice == "5":
                header("PROMETHEUS METRICS EXPORT / READ ONLY")
                suggested = tls_ops.default_metrics_cluster_label(context)
                hint("This is a monitoring label, not a Kubernetes cluster selector.")
                hint("Only aggregate certificate validity counts are exported.")
                label = ask("Prometheus cluster label (letters/digits/._-)", suggested)
                text_data = tls_ops.prometheus_metrics(rows, label)
                saved = tls_ops.atomic_evidence(report_root, "metrics",
                                               {"context": context, "cluster_label": label,
                                                "namespaces": namespaces,
                                                "metrics": text_data})
                prom = saved.with_name("kaori_tls.prom")
                with prom.open("x", encoding="utf-8") as stream:
                    stream.write(text_data)
                prom.chmod(0o600)
                print(f"  Cluster label: {label}")
                file_hint("Prometheus textfile; not published automatically", prom)
                file_hint("Local export evidence", saved)
                hint("The file is not pushed to Prometheus; configure your approved textfile collector.")
            ok("Read-only utility completed. Kubernetes Secrets were not modified.")
        except (Stop, OSError, ValueError, KeyError, TypeError) as exc:
            warning(f"Diagnostic STOP: {exc}")
            hint("No automatic updates or rollback. Check RBAC, context, and scope.")
            if ask("Return to Toolbox? Type YES", "YES") != "YES":
                return


def reverify_existing_run(args):
    """Verification-only on a previously written run; never invokes renew."""
    plan_location = choose_previous_plan(args, purpose="reverify")
    if not plan_location:
        return
    path = Path(plan_location).resolve()
    plan = json.loads(path.read_text(encoding="utf-8"))
    check(plan.get("schema_version") == 1 and plan_id(plan) == plan.get("plan_id"),
          "Plan identity invalid")
    journal_path = path.parent / "execution-journal.json"
    check(journal_path.is_file(), "No execution journal: this run was never executed")
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    allowed = ("COMPLETE_ENDPOINT_UNVERIFIED", "COMPLETE_ENDPOINT_VERIFIED",
               "COMPLETE_WITH_STAGED_SECRETS", "COMPLETE_WITH_HELD_TARGETS",
               "COMPLETE_WITH_HELD_AND_STAGED", "COMPLETE_WITH_EXTERNAL_TLS")
    check(journal.get("status") in allowed,
          "Journal status does not allow endpoint reverification; use Run Reconciliation.")
    workspace = path.parent.parent.parent
    endpoints = workspace / "endpoints.csv"
    staged = workspace / "staged-targets.csv"
    check(endpoints.is_file() and not endpoints.is_symlink(),
          "HTTPS mapping file missing; check endpoints.csv. Do not invent endpoints.")
    ctx = plan["context"]
    contexts = exec_read(["kubectl", "config", "get-contexts", "-o", "name"]).splitlines()
    check(ctx in contexts, "Previous Kubernetes context is missing from kubeconfig")
    header("REVERIFY ENDPOINTS WITHOUT RENEWAL")
    print("Context: ", ctx)
    print("Plan ID: ", plan["plan_id"])
    print("Journal: ", journal["status"])
    file_hint("Mapping TLS (using the saved mapping as-is)", endpoints)
    if staged.is_file():
        file_hint("Staged Secret (per approved mapping)", staged)
    warning("KUBERNETES READ-ONLY: local journal/evidence files will be updated, not TLS Secrets.")
    check(ask("Type VERIFY to perform HTTPS verification only") == "VERIFY",
          "Operator cancelled endpoint reverification")
    trust = ask("Internal CA bundle (Enter for system trust)", "")
    cmd = ["verify-endpoints", "--plan", path, "--endpoints", endpoints]
    if staged.is_file():
        cmd += ["--staged-targets", staged]
    if trust:
        cmd += ["--ca-bundle", Path(trust).expanduser().resolve()]
    issue = None
    try:
        helper(ctx, "verify", "--plan", path)
        helper(ctx, *cmd)
    except Stop as exc:
        issue = exc
        operator_error_message(str(exc), path.parent)
    finally:
        try:
            helper(None, "report", "--plan", path)
        except Stop as exc:
            warning("Report incomplete: " + str(exc))
    file_hint("Updated journal", journal_path)
    file_hint("Endpoint evidence", path.parent / "endpoint-verification.json")
    file_hint("Renewal report", path.parent / "renewal-report.csv")
    if issue:
        raise Stop("Endpoints are still failing or mismatched. Do not repeat renewal.")
    ok("Endpoint reverification completed without changing Kubernetes Secrets.")



def crud_command(context, command, *options):
    """Run the standalone CRUD engine, keeping the historical KAORI UI.

    Writes have no arbitrary timeout: an API request may have succeeded despite
    a client timeout. The CRUD engine records uncertain outcomes before writes.
    """
    tool = HERE.parents[1] / "tls_crud.py"
    check(tool.is_file(), "CRUD engine is unavailable in this checkout")
    write = command in ("create", "update", "delete")
    argv = [sys.executable, str(tool), "--context", context, command,
            *list(map(str, options))]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=None if write else 180)
    except subprocess.TimeoutExpired as exc:
        raise Stop("CRUD preflight timed out; inspect live state before retrying") from exc
    if proc.returncode:
        # The CLI returns controlled STOP messages, never raw TLS key material.
        raise Stop(proc.stderr.strip() or "CRUD operation was stopped")
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise Stop("Unexpected CRUD CLI response; check local execution logs") from exc


def local_recovery_identity():
    """Prepare the age recovery identity once; never print or export private key data."""
    home = Path.home()
    identity = home / ".config" / "age" / "k8s-tls-recovery.txt"
    if not identity.exists():
        identity = home / ".config" / "kaori-tls" / "recovery.agekey"
        if not identity.exists():
            warning("A protected age recovery key is needed before deleting a Secret.")
            hint("KAORI can generate it once; later Delete runs reuse it automatically.")
            check(ask("Type SETUP to create a local recovery key (Enter=Back)") == "SETUP",
                  "Recovery key setup cancelled")
            folder = identity.parent
            check(not folder.is_symlink() and not identity.is_symlink(),
                  "Recovery key directory/path must not be a symlink")
            folder.mkdir(parents=True, mode=0o700, exist_ok=True)
            check(folder.stat().st_mode & 0o077 == 0,
                  "Recovery key directory must be private (0700)")
            proc = subprocess.run(["age-keygen", "-o", str(identity)],
                                  capture_output=True, text=True, timeout=30)
            check(proc.returncode == 0, "Unable to generate age recovery key")
            identity.chmod(0o600)
            print("  Recovery key created in your private local configuration.")
            warning("Keep a separate secure copy. If you lose this key, backups cannot be restored.")
            check(ask("Type RECOVERY to acknowledge backup-key custody") == "RECOVERY",
                  "Recovery-key custody not confirmed; Delete cancelled")
    check(identity.is_file() and not identity.is_symlink() and
          identity.stat().st_mode & 0o077 == 0,
          "Local recovery identity missing or unsafe (file must be 0600)")
    proc = subprocess.run(["age-keygen", "-y", str(identity)],
                          capture_output=True, text=True, timeout=30)
    recipient = proc.stdout.strip()
    check(proc.returncode == 0 and recipient.startswith("age1") and len(recipient) > 20,
          "Unable to read the matching age public backup recipient")
    return identity, recipient


def crud_wizard(args, operation):
    """One-person guided Create/Delete; retain immutable plans and fail-closed writes."""
    check(operation in ("create", "delete"), "Unsupported lifecycle operation")
    is_delete = operation == "delete"
    action = operation.upper()
    header(f"{action} TLS SECRET / GUIDED CHANGE")
    hint("Single-operator mode: no separate approval documents or signatures.")
    hint("Read-only planning first; all Kubernetes writes require explicit confirmation.")
    if is_delete:
        warning("Delete is permanent until separately restored from an encrypted backup.")
        hint("Active references, controller ownership, or unknown dependencies still BLOCK Delete.")
    else:
        hint("Create never overwrites an existing Secret; provide a valid PEM/key pair.")

    contexts = exec_read(["kubectl", "config", "get-contexts", "-o", "name"]).splitlines()
    context = args.context or choose("Kubernetes context", contexts)
    check(context in contexts, "Unknown Kubernetes context")
    ns_data = json.loads(exec_read(["kubectl", "--context", context,
                                   "--request-timeout=20s", "get", "namespaces", "-o", "json"]))
    namespace = choose("Target namespace", sorted(
        x["metadata"]["name"] for x in ns_data["items"]))
    name = ask("Exact TLS Secret name (BACK to cancel)")
    check(bool(name) and not any(ch.isspace() for ch in name) and
          not name.startswith("-"), "Invalid target Secret name")
    workspace = Path(ask("Private evidence root (outside source repository)",
                         str(Path.home() / "k8s-tls-private" / "crud-runs"))).expanduser()
    check(not workspace.is_symlink() and HERE not in workspace.resolve().parents,
          "Evidence cannot be written to the source checkout")
    options = ["--namespace", namespace, "--secret", name, "--workspace", workspace]
    cert = key = ca = None
    backup_identity = backup_recipient = None
    if not is_delete:
        cert, key, ca = choose_certificate_inputs(args)
        options += ["--cert", cert, "--key", key]
        if ca:
            options += ["--ca-bundle", ca]

    step(1, 3, "Read-only target checks and immutable plan",
         "Nothing will be created or deleted during this step.")
    result = crud_command(context, "plan-delete" if is_delete else "plan-create", *options)
    if is_delete and result.get("status") == "HOLD":
        header("DELETE ON HOLD / READ ONLY")
        print(f"  Target : {result['target']}")
        print(f"  Reason : {result['reason']}")
        print()
        print("  Detected blockers:")
        for blocker in result.get("blockers", []):
            print(f"  - {blocker}")
        print()
        warning("Delete is BLOCKED. No executable plan or Kubernetes write was created.")
        hint("Remove the dependency through its normal change process, then re-run the check.")
        hint("A clean Kubernetes scan cannot prove there are no external consumers.")
        file_hint("Read-only HOLD evidence", result["evidence"])
        return result
    plan_path = Path(result["plan"]).expanduser().resolve()
    planid = result["plan_id"]
    file_hint("Immutable lifecycle plan", plan_path)
    print(f"  Context : {context}")
    print(f"  Target  : {namespace}/{name}")
    print(f"  Action  : {action}")
    print(f"  Plan ID : {planid}")
    hint("Plan expires in 30 minutes. Enter leaves this as a read-only plan.")
    if ask(f"Type PROCEED to review and confirm {action} (Enter=Plan only)") != "PROCEED":
        ok("Plan saved only. Kubernetes Secrets were not modified.")
        return result

    step(2, 3, "Operator review and explicit confirmation",
         "One target, one attempt. Kubernetes state is checked again before mutation.")
    if is_delete:
        warning("Review dependencies beyond Kubernetes (proxy, LB, monitoring, external consumers).")
        check(ask("Type UNUSED to confirm the Secret has no external consumers") == "UNUSED",
              "Delete cancelled: external consumer safety not confirmed")
    exact_target = f"{namespace}/{name}"
    check(ask(f"Type {action} {exact_target} to confirm") == f"{action} {exact_target}",
          "Operation and target confirmation did not match")
    hint(f"Immutable Plan ID {planid} is bound and verified automatically.")
    if is_delete:
        # Only provision recovery once a delete is proven eligible and authorized;
        # HOLD and plan-only checks must not create local keys or request setup.
        backup_identity, backup_recipient = local_recovery_identity()
        ok("Encrypted backup recovery key is available.")

    step(3, 3, "Execute once and verify Kubernetes response",
         "Encrypted recovery backup is validated BEFORE Delete; no automatic retry.")
    apply_args = ["--namespace", namespace, "--secret", name,
                  "--plan", plan_path, "--approve", planid,
                  "--confirm-target", exact_target,
                  "--operator-mode", "--operator-ack", f"{action} {exact_target}"]
    if is_delete:
        apply_args += ["--operator-attested",
                       "--backup-recipient", backup_recipient,
                       "--backup-identity", backup_identity]
    else:
        apply_args += ["--cert", cert, "--key", key]
        if ca:
            apply_args += ["--ca-bundle", ca]
    outcome = crud_command(context, operation, *apply_args)
    ok(f"{action}: {outcome['status']}")
    file_hint("Lifecycle journal", outcome["journal"])
    if is_delete:
        file_hint("Encrypted recovery backup",
                  plan_path.with_name(f"delete-{planid}-backup.age"))
        hint("Preserve the backup, plan, journal and recovery key. Restore is a separate action.")
    return outcome


def main_menu(args):
    os.umask(0o077)
    check(sys.stdin.isatty(), "Interactive TTY required")
    while True:
        brand_banner()
        history = recent_plans(args)
        count = len(history)
        print(f"  {count} saved {'run' if count == 1 else 'runs'}"
              "  |  Default: Inventory (read-only)")
        print()
        menu_entry("1", "Inventory", default=True)
        menu_entry("2", "Expiry audit")
        menu_entry("3", "TLS Toolbox")
        menu_entry("4", "Reverify HTTPS")
        print()
        menu_entry("5", "Renew TLS", caution=True)
        menu_entry("6", "Review HOLD")
        print()
        menu_entry("7", "Run history")
        menu_entry("8", "Status guide")
        menu_entry("9", "Help")
        print()
        menu_entry("10", "Create TLS Secret", caution=True)
        menu_entry("11", "Delete TLS Secret", caution=True)
        menu_entry("0", "Exit")
        print()
        try:
            choice = ask("Select menu (? for Help)", "1").strip().upper()
        except (KeyboardInterrupt, EOFError):
            print()
            ok("Menu closed; no new operation started.")
            return
        if choice == "0":
            ok("Exiting the TLS manager.")
            return
        try:
            if choice in ("9", "?", "H", "HELP"):
                show_operator_help()
                continue
            if choice == "1":
                tls_discovery_dashboard(args)
                continue
            if choice == "2":
                audit_secret_validity(args)
                continue
            if choice == "3":
                toolkit_menu(args)
                continue
            if choice == "4":
                reverify_existing_run(args)
                continue
            if choice == "5":
                wizard(args)
                continue
            if choice == "6":
                plan_path = choose_previous_plan(args, held_only=True)
                if not plan_path:
                    continue
                args.review_plan = plan_path
                output = review_hold_plan(args)
                if output and ask("Start a NEW renewal using this review? Type YES", "no") == "YES":
                    args.reviewed_holds = str(output)
                    args.review_plan = None
                    wizard(args)
                continue
            if choice == "7":
                path = choose_previous_plan(args)
                if path:
                    show_run_status(path)
                continue
            if choice == "10":
                crud_wizard(args, "create")
                continue
            if choice == "11":
                crud_wizard(args, "delete")
                continue
            if choice == "8":
                header("STATUS REFERENCE GUIDE")
                for status in STATUS_GUIDE:
                    status_help(status)
                continue
            warning("Unknown menu option. Choose a displayed number, ? or H for Help.")
        except Stop as exc:
            warning("Operation cancelled/stopped: " + str(exc))
            operator_error_message(str(exc), getattr(args, "_last_run_dir", None))
            hint("Returning to menu. If a write was attempted, inspect the execution journal.")



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", help="Initial kubectl context; must exist")
    parser.add_argument("--workspace", help="Private output root; never inside Git repo")
    parser.add_argument("--cert", help="Replacement leaf-first fullchain PEM path")
    parser.add_argument("--key", help="Matching PEM private key path")
    parser.add_argument("--ca-bundle", help="Approved custom CA path")
    parser.add_argument("--reviewed-holds", help="Approved fingerprint-pinned exceptions CSV")
    parser.add_argument("--review-plan", help="Review HELD targets from an earlier plan without Kubernetes changes")
    parser.add_argument("--plain", action="store_true", help="Disable colors and emoji")
    args = parser.parse_args()
    setup_display(args.plain)
    try:
        if args.review_plan:
            review_hold_plan(args)
        else:
            main_menu(args)
        return 0
    except (Stop, ValueError, OSError, EOFError, KeyboardInterrupt,
            subprocess.TimeoutExpired, json.JSONDecodeError) as ex:
        print(f"\n{icon('stop')} STOP: {ex}", file=sys.stderr)
        operator_error_message(str(ex), getattr(args, "_last_run_dir", None))
        return 1


if __name__ == "__main__":
    sys.exit(main())
