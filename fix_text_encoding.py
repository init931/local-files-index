from __future__ import annotations

import argparse
import json

from encoding_tools import DEFAULT_CANDIDATE_ENCODINGS, fix_file_encoding


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fix a text file by decoding it with the right source encoding and writing UTF-8 output."
    )
    parser.add_argument("path", help="Path to the text file")
    parser.add_argument(
        "--source-encoding",
        default=None,
        help="Known source encoding, for example cp1251",
    )
    parser.add_argument(
        "--target-encoding",
        default="utf-8",
        help="Output encoding. Default: utf-8",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output file path. By default a sibling *.utf-8.txt file is created.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the original file instead of creating a new one",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create a .bak file before overwriting the original",
    )
    parser.add_argument(
        "--no-preserve-metadata",
        action="store_true",
        help="Do not copy source file metadata to the output file",
    )
    parser.add_argument(
        "--recover-mojibake",
        action="store_true",
        help="Try common re-encode/decode repairs if the decoded text still looks broken",
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
        help="Candidate encodings to test when source encoding is not provided",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of a text summary",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    result = fix_file_encoding(
        args.path,
        source_encoding=args.source_encoding,
        target_encoding=args.target_encoding,
        output_path=args.output,
        overwrite=args.overwrite,
        backup=not args.no_backup,
        preserve_metadata=not args.no_preserve_metadata,
        recover_mojibake=args.recover_mojibake,
        candidate_encodings=args.encodings,
        script_hint=args.script_hint,
    )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print(f"Input file: {result['input_path']}")
    print(f"Output file: {result['output_path']}")
    print(f"Source encoding used: {result['source_encoding']}")
    print(f"Target encoding: {result['target_encoding']}")
    if result["backup_path"]:
        print(f"Backup file: {result['backup_path']}")
    print(f"Preserve metadata: {result['preserve_metadata']}")
    print(f"Metadata preserved: {result['metadata_preserved']}")
    if result["metadata_error"]:
        print(f"Metadata preserve error: {result['metadata_error']}")
    print(f"Mojibake recovery applied: {result['recover_mojibake']}")
    print(f"Recovery changed text: {result['recovery_changed_text']}")
    print(f"Recovery strategy: {result['recovery_strategy']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
