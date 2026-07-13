"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import __version__
from .grading import GRADE_ORDER, meets
from .models import ScanResult
from .report import render, render_batch
from .scanner import scan

# Scans are almost pure network wait, so threads parallelize them well.
_MAX_WORKERS = 8


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headguard",
        description="Scan a site's HTTP security headers and grade its hardening.",
    )
    parser.add_argument(
        "urls", nargs="+", metavar="URL",
        help="one or more URLs to scan (scheme defaults to https://); "
             "with several URLs, a comparison table is shown instead of full reports",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="print the scan result as JSON (an object for one URL, an array for several)",
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
        help="exit with status 1 if any grade is below this (useful in CI); "
             "one of: E, D, C, B, A, A+",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    def scan_one(url: str) -> tuple[str, ScanResult | None, str | None]:
        try:
            return url, scan(url, timeout=args.timeout, verify=not args.insecure), None
        except httpx.HTTPError as exc:
            return url, None, str(exc)

    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(args.urls))) as pool:
        items = list(pool.map(scan_one, args.urls))

    single = len(items) == 1

    if args.json:
        payload = [
            result.to_dict() if result is not None else {"url": url, "error": error}
            for url, result, error in items
        ]
        print(json.dumps(payload[0] if single else payload, indent=2))
    elif single:
        url, result, error = items[0]
        if error is not None:
            print(f"error: could not scan {url}: {error}", file=sys.stderr)
        else:
            render(result)
    else:
        render_batch(items)

    if any(error is not None for _, _, error in items):
        return 2

    if args.min_grade:
        failing = [r for _, r, _ in items if r is not None and not meets(r.grade, args.min_grade)]
        if failing:
            for result in failing:
                print(
                    f"{result.final_url}: grade {result.grade} is below the "
                    f"required minimum {args.min_grade}",
                    file=sys.stderr,
                )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
