#!/usr/bin/env python3
"""KAORI interactive operator console (READ and PLAN ONLY).

No write entrypoint exists here. Mutating CRUD commands require signed approval
via the explicit non-interactive CLI. When the archived renewal wizard has been
migrated and audited, the unified launcher can use that wizard by default.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent


def banner():
    print(r"""
   _  __    _    ___  ____  ___
  | |/ /   / \  / _ \|  _ \|_ _|
  | ' /   / _ \| | | | |_) || |
  | . \  / ___ \ |_| |  _ < | |
  |_|\_\/_/   \_\___/|_| \_\___|
  TLS SECRET MANAGER
  --------------------------------------------
  READ / PLAN actions only. Writes require signed CLI approval.
""")


def ask(question, default=""):
    suffix = f" [{default}]" if default else ""
    value = input(f"{question}{suffix}: ").strip()
    if value.upper() == "BACK":
        raise KeyboardInterrupt
    return value or default


def action_args(choice, prompt=None):
    """Generate only read/plan tokens, never create/update/delete write tokens."""
    prompt = ask if prompt is None else prompt
    commands = {"1": "inventory", "2": "inspect", "3": "plan-create",
                "4": "plan-update", "5": "plan-delete"}
    if choice not in commands:
        return None
    context = prompt("Kubernetes context").strip()
    namespace = prompt("Namespace").strip()
    if not context or not namespace:
        print("Context and namespace are required. No operation started.")
        return None
    args = ["--context", context, commands[choice], "--namespace", namespace]
    if choice != "1":
        secret = prompt("TLS Secret name").strip()
        if not secret:
            print("Secret name is required. No operation started.")
            return None
        args.extend(["--secret", secret])
    if choice in ("3", "4"):
        cert = prompt("Certificate PEM path").strip()
        key = prompt("Private key PEM path").strip()
        if not cert or not key:
            print("Both PEM paths are required. No operation started.")
            return None
        args.extend(["--cert", cert, "--key", key])
    if choice in ("3", "4", "5"):
        root = prompt("Private evidence directory", str(
            Path.home() / ".local" / "share" / "kaori-tls-private")).strip()
        if not root:
            print("Private evidence directory required. No operation started.")
            return None
        args.extend(["--workspace", root])
    return args


def main():
    if not sys.stdin.isatty():
        print("Interactive mode requires a TTY. Use explicit CLI commands.", file=sys.stderr)
        return 2
    os.umask(0o077)
    import tls_crud
    while True:
        banner()
        for no, name in (("1", "Inventory (read-only)"),
                         ("2", "Inspect TLS Secret"),
                         ("3", "Plan Create TLS"),
                         ("4", "Plan Update TLS"),
                         ("5", "Plan Delete TLS"),
                         ("6", "Advanced renewal (migration pending)"),
                         ("7", "Help"),
                         ("0", "Exit")):
            print(f"  {no:>2}. {name}")
        try:
            choice = ask("Select menu (? for Help)", "0").upper()
            if choice == "0":
                return 0
            if choice in ("7", "?", "H", "HELP"):
                print("Inventory/Inspect are read-only. Plan commands create private local evidence.")
                print("Signed approval and an exact PLAN ID are required for all writes.")
                print("Advanced renewal is restored after sanitized migration and regression.")
                continue
            if choice == "6":
                print("Advanced renewal unavailable until legacy migration passes security review.")
                continue
            arguments = action_args(choice)
            if arguments is None:
                print("Select one of the displayed numbers.")
                continue
            code = tls_crud.main(arguments)
            if code:
                print("STOP. Review the error and do not blindly retry a mutation.")
        except (KeyboardInterrupt, EOFError):
            print("\nMenu closed. No Kubernetes Secret write initiated by this menu.")
            return 0


if __name__ == "__main__":
    sys.exit(main())
