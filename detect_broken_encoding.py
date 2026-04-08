from __future__ import annotations

import argparse
import json

from encoding_tools import (
    DEFAULT_CANDIDATE_ENCODINGS,
    analyze_file,
    detect_encoding_issue,
    format_results_table,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect suspicious or broken text encodings."
    )
    parser.add_argument("path", help="Path to the text file")
    parser.add_argument(
        "--expected-encoding",
        default=None,
        help="Encoding you believe the file should use, for example cp1251",
    )
    parser.add_argument(
        "--script-hint",
        choices=["auto", "cyrillic", "latin"],
        default="cyrillic",
        help="Bias scoring toward the expected writing system",
    )
    parser.add_argument(
        "--encodings",
        nargs="+",
        default=list(DEFAULT_CANDIDATE_ENCODINGS),
        help="Candidate encodings to test",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of a text table",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    results = analyze_file(
        args.path,
        candidate_encodings=args.encodings,
        script_hint=args.script_hint,
    )
    analysis = detect_encoding_issue(
        args.path,
        candidate_encodings=args.encodings,
        expected_encoding=args.expected_encoding,
        script_hint=args.script_hint,
    )

    if args.json:
        print(json.dumps(analysis, ensure_ascii=False, indent=2))
        return 0

    print(format_results_table(results))
    print()

    best = analysis["best"]
    if best:
        print(
            f"Best candidate: {best['encoding']} | score={best['suspicious_score']} | "
            f"script_ratio={best['script_ratio']}"
        )
    else:
        print("Best candidate: none")

    print(f"Likely broken: {'yes' if analysis['likely_broken'] else 'no'}")

    if analysis["expected_encoding"] is not None:
        print(
            f"Expected encoding '{analysis['expected_encoding']}' decode OK: "
            f"{analysis['expected_ok']}"
        )
        if analysis["expected_error"]:
            print(f"Expected decode error: {analysis['expected_error']}")

    for reason in analysis["reasons"]:
        print(f"Reason: {reason}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
