from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence
import math
import shutil
import unicodedata


DEFAULT_CANDIDATE_ENCODINGS = (
    "utf-8",
    "utf-8-sig",
    "cp1251",
    "cp866",
    "koi8-r",
    "mac_cyrillic",
    "latin-1",
    "cp1252",
)

MOJIBAKE_MARKERS = ("Ð", "Ñ", "Ã", "Â", "¤", "�")
RECOVERY_PAIRS = (
    ("latin-1", "utf-8"),
    ("cp1252", "utf-8"),
    ("cp1251", "utf-8"),
    ("cp866", "utf-8"),
    ("koi8-r", "utf-8"),
)


@dataclass(slots=True)
class CandidateResult:
    encoding: str
    can_decode: bool
    suspicious_score: float
    script_ratio: float
    replacement_count: int
    control_count: int
    mojibake_count: int
    sample: str
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["suspicious_score"] = round(float(self.suspicious_score), 2)
        payload["script_ratio"] = round(float(self.script_ratio), 3)
        return payload


def _is_cyrillic(char: str) -> bool:
    return "CYRILLIC" in unicodedata.name(char, "")


def _is_latinish(char: str) -> bool:
    if not char.isalpha():
        return False
    return "LATIN" in unicodedata.name(char, "")


def _sample_text(text: str, limit: int = 90) -> str:
    sample = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return sample[:limit]


def _script_ratio(text: str, script_hint: str) -> float:
    letters = [char for char in text if char.isalpha()]
    if not letters:
        return 0.0

    if script_hint == "cyrillic":
        hits = sum(_is_cyrillic(char) for char in letters)
    elif script_hint == "latin":
        hits = sum(_is_latinish(char) for char in letters)
    else:
        return 0.0

    return hits / len(letters)


def score_text(text: str, script_hint: str = "auto") -> dict[str, float | int]:
    replacement_count = text.count("\ufffd")
    control_count = sum(
        1
        for char in text
        if unicodedata.category(char).startswith("C") and char not in "\r\n\t"
    )
    mojibake_count = sum(text.count(marker) for marker in MOJIBAKE_MARKERS)
    script_ratio = _script_ratio(text, script_hint)

    letters = [char for char in text if char.isalpha()]
    latinish_ratio = 0.0
    if letters:
        latinish_ratio = sum(_is_latinish(char) for char in letters) / len(letters)

    score = float(replacement_count * 40 + control_count * 25 + mojibake_count * 10)
    if script_hint == "cyrillic":
        score += max(0.55 - script_ratio, 0.0) * 20
        score += latinish_ratio * 10
    elif script_hint == "latin":
        score += max(0.55 - script_ratio, 0.0) * 20

    if not text.strip():
        score += 15
    if "\x00" in text:
        score += 100

    return {
        "suspicious_score": round(score, 2),
        "script_ratio": round(script_ratio, 3),
        "replacement_count": replacement_count,
        "control_count": control_count,
        "mojibake_count": mojibake_count,
    }


def analyze_bytes(
    raw_bytes: bytes,
    candidate_encodings: Sequence[str] = DEFAULT_CANDIDATE_ENCODINGS,
    script_hint: str = "auto",
) -> list[CandidateResult]:
    results: list[CandidateResult] = []
    for encoding in candidate_encodings:
        try:
            text = raw_bytes.decode(encoding, errors="strict")
        except (LookupError, UnicodeDecodeError) as exc:
            results.append(
                CandidateResult(
                    encoding=encoding,
                    can_decode=False,
                    suspicious_score=math.inf,
                    script_ratio=0.0,
                    replacement_count=0,
                    control_count=0,
                    mojibake_count=0,
                    sample="",
                    error=str(exc),
                )
            )
            continue

        metrics = score_text(text, script_hint=script_hint)
        results.append(
            CandidateResult(
                encoding=encoding,
                can_decode=True,
                suspicious_score=float(metrics["suspicious_score"]),
                script_ratio=float(metrics["script_ratio"]),
                replacement_count=int(metrics["replacement_count"]),
                control_count=int(metrics["control_count"]),
                mojibake_count=int(metrics["mojibake_count"]),
                sample=_sample_text(text),
            )
        )

    return sorted(
        results,
        key=lambda item: (
            not item.can_decode,
            item.suspicious_score,
            -item.script_ratio,
            item.encoding,
        ),
    )


def analyze_file(
    path: str | Path,
    candidate_encodings: Sequence[str] = DEFAULT_CANDIDATE_ENCODINGS,
    script_hint: str = "auto",
) -> list[dict[str, object]]:
    raw_bytes = Path(path).read_bytes()
    return [
        candidate.to_dict()
        for candidate in analyze_bytes(
            raw_bytes,
            candidate_encodings=candidate_encodings,
            script_hint=script_hint,
        )
    ]


def best_candidate(results: Sequence[dict[str, object]]) -> dict[str, object] | None:
    for result in results:
        if result["can_decode"]:
            return result
    return None


def detect_encoding_issue(
    path: str | Path,
    candidate_encodings: Sequence[str] = DEFAULT_CANDIDATE_ENCODINGS,
    expected_encoding: str | None = None,
    script_hint: str = "auto",
    suspicious_threshold: float = 8.0,
) -> dict[str, object]:
    path_obj = Path(path)
    raw_bytes = path_obj.read_bytes()
    results = analyze_bytes(
        raw_bytes,
        candidate_encodings=candidate_encodings,
        script_hint=script_hint,
    )
    result_dicts = [item.to_dict() for item in results]
    best = best_candidate(result_dicts)

    expected_ok = None
    expected_error = None
    if expected_encoding is not None:
        try:
            raw_bytes.decode(expected_encoding, errors="strict")
            expected_ok = True
        except (LookupError, UnicodeDecodeError) as exc:
            expected_ok = False
            expected_error = str(exc)

    reasons: list[str] = []
    likely_broken = False
    if best is None:
        likely_broken = True
        reasons.append("No candidate encoding could decode the file without errors.")
    elif float(best["suspicious_score"]) >= suspicious_threshold:
        likely_broken = True
        reasons.append(
            "The best decoding still looks suspicious based on replacement characters, controls, or mojibake markers."
        )

    if expected_ok is False:
        likely_broken = True
        reasons.append(
            f"The expected encoding '{expected_encoding}' cannot decode the file cleanly."
        )

    return {
        "path": str(path_obj),
        "script_hint": script_hint,
        "candidate_results": result_dicts,
        "best": best,
        "likely_broken": likely_broken,
        "expected_encoding": expected_encoding,
        "expected_ok": expected_ok,
        "expected_error": expected_error,
        "reasons": reasons,
    }


def recover_mojibake_text(text: str, script_hint: str = "auto") -> dict[str, object]:
    best_text = text
    best_score = score_text(text, script_hint=script_hint)
    strategy = "original"

    for wrong_encoding, correct_encoding in RECOVERY_PAIRS:
        try:
            candidate = text.encode(wrong_encoding).decode(correct_encoding)
        except (LookupError, UnicodeEncodeError, UnicodeDecodeError):
            continue

        candidate_score = score_text(candidate, script_hint=script_hint)
        if float(candidate_score["suspicious_score"]) < float(best_score["suspicious_score"]):
            best_text = candidate
            best_score = candidate_score
            strategy = f"encode as {wrong_encoding}, decode as {correct_encoding}"

    return {
        "text": best_text,
        "changed": best_text != text,
        "strategy": strategy,
        "score": best_score,
    }


def default_output_path(path: str | Path, target_encoding: str) -> Path:
    path_obj = Path(path)
    suffix = path_obj.suffix or ".txt"
    return path_obj.with_name(f"{path_obj.stem}.{target_encoding}{suffix}")


def fix_file_encoding(
    path: str | Path,
    source_encoding: str | None = None,
    target_encoding: str = "utf-8",
    output_path: str | Path | None = None,
    overwrite: bool = False,
    backup: bool = True,
    preserve_metadata: bool = True,
    recover_mojibake: bool = False,
    candidate_encodings: Sequence[str] = DEFAULT_CANDIDATE_ENCODINGS,
    script_hint: str = "auto",
) -> dict[str, object]:
    path_obj = Path(path)
    raw_bytes = path_obj.read_bytes()
    analysis = detect_encoding_issue(
        path_obj,
        candidate_encodings=candidate_encodings,
        script_hint=script_hint,
    )

    chosen_encoding = source_encoding
    if chosen_encoding is None:
        best = analysis["best"]
        if best is None:
            raise ValueError("Could not determine a working source encoding.")
        chosen_encoding = str(best["encoding"])

    text = raw_bytes.decode(chosen_encoding, errors="strict")
    recovery = {
        "changed": False,
        "strategy": "not_applied",
        "score": score_text(text, script_hint=script_hint),
    }
    if recover_mojibake:
        recovery = recover_mojibake_text(text, script_hint=script_hint)
        text = str(recovery["text"])

    destination = Path(output_path) if output_path is not None else default_output_path(path_obj, target_encoding)
    if overwrite:
        destination = path_obj if output_path is None else Path(output_path)

    backup_path = None
    if destination == path_obj and backup:
        backup_path = path_obj.with_name(f"{path_obj.name}.bak")
        if not backup_path.exists():
            backup_path.write_bytes(raw_bytes)

    destination.write_bytes(text.encode(target_encoding))

    metadata_preserved = False
    metadata_error = None
    if preserve_metadata and destination != path_obj:
        try:
            shutil.copystat(path_obj, destination)
            metadata_preserved = True
        except OSError as exc:
            metadata_error = str(exc)

    return {
        "input_path": str(path_obj),
        "output_path": str(destination),
        "backup_path": str(backup_path) if backup_path is not None else None,
        "source_encoding": chosen_encoding,
        "target_encoding": target_encoding,
        "preserve_metadata": preserve_metadata,
        "metadata_preserved": metadata_preserved,
        "metadata_error": metadata_error,
        "recover_mojibake": recover_mojibake,
        "recovery_changed_text": recovery["changed"],
        "recovery_strategy": recovery["strategy"],
        "analysis": analysis,
    }


def format_results_table(results: Iterable[dict[str, object]]) -> str:
    rows = list(results)
    headers = ["encoding", "ok", "score", "script", "sample"]
    matrix = [headers]
    for row in rows:
        matrix.append(
            [
                str(row["encoding"]),
                "yes" if row["can_decode"] else "no",
                "inf" if row["suspicious_score"] == math.inf else str(row["suspicious_score"]),
                str(row["script_ratio"]),
                str(row["sample"]),
            ]
        )

    widths = [max(len(line[column]) for line in matrix) for column in range(len(headers))]
    formatted_rows = []
    for index, row in enumerate(matrix):
        formatted_rows.append(
            " | ".join(value.ljust(widths[column]) for column, value in enumerate(row))
        )
        if index == 0:
            formatted_rows.append("-+-".join("-" * width for width in widths))

    return "\n".join(formatted_rows)
