"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys

import httpx

from . import __version__
from .grading import GRADE_ORDER, meets
from .report import render, to_json
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headguard",
        description="Scan a site's HTTP security headers and grade its hardening.",
    )
    parser.add_argument("url", help="URL to scan (scheme defaults to https://)")
    parser.add_argument(
        "--json", action="store_true",
        help="print the scan result as JSON instead of the table",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, metavar="SECONDS",
        help="request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="skip TLS certificate verification",
    )
    parser.add_argument(
        "--min-grade", choices=[g for g in GRADE_ORDER if g != "F"], metavar="GRADE",
        help="exit with status 1 if the grade is below this (useful in CI); "
             "one of: E, D, C, B, A, A+",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = scan(args.url, timeout=args.timeout, verify=not args.insecure)
    except httpx.HTTPError as exc:
        print(f"error: could not scan {args.url}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(to_json(result))
    else:
        render(result)

    if args.min_grade and not meets(result.grade, args.min_grade):
        print(
            f"grade {result.grade} is below the required minimum {args.min_grade}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
