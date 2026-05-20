from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import SEVERITY_RANK
from .reporters import render_report
from .scanner import scan_path
from .web import DEFAULT_HOST, DEFAULT_PORT, serve_ui


def build_scan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="awal",
        description="Check whether a README matches the repo a fresh developer just cloned.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository path to scan.")
    parser.add_argument("--format", choices=("text", "json", "csv", "sarif"), default="text")
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_RANK), default="high")
    parser.add_argument("--output", help="Write report to a file.")
    return parser


def build_ui_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="awal ui",
        description="Start the local Awal web UI.",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind. Defaults to 127.0.0.1.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind.")
    parser.add_argument("--open", action="store_true", help="Open the UI in your browser.")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if raw_args and raw_args[0] == "ui":
        parser = build_ui_parser()
        args = parser.parse_args(raw_args[1:])
        serve_ui(args.host, args.port, open_browser=args.open)
        return 0
    if raw_args and raw_args[0] == "scan":
        raw_args = raw_args[1:]

    parser = build_scan_parser()
    args = parser.parse_args(raw_args)
    report = scan_path(Path(args.path), fail_on=args.fail_on)
    rendered = render_report(report, args.format)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if report.status == "block":
        return 2
    if report.status == "review":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
