"""Extract, defang, and refang common indicators of compromise.

The module intentionally uses only the Python standard library so it is easy to
review, run, and reuse in small blue-team labs.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


TRAILING_PUNCTUATION = ".,;:)]}'\""

PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE),
}


@dataclass(frozen=True, order=True)
class Indicator:
    """A normalized indicator extracted from text."""

    type: str
    value: str
    defanged: str


def defang(value: str) -> str:
    """Return a safe-to-share representation of an indicator."""

    result = value.strip()
    result = re.sub(r"(?i)^https://", "hxxps://", result)
    result = re.sub(r"(?i)^http://", "hxxp://", result)
    result = result.replace("@", "[@]")
    result = result.replace(".", "[.]")
    return result


def refang(value: str) -> str:
    """Convert a defanged indicator back to its standard representation."""

    result = value.strip()
    result = re.sub(r"(?i)^hxxps://", "https://", result)
    result = re.sub(r"(?i)^hxxp://", "http://", result)
    result = result.replace("[@]", "@")
    result = result.replace("[.]", ".")
    return result


def _clean_match(value: str) -> str:
    return value.strip().rstrip(TRAILING_PUNCTUATION)


def _covered_by_existing(value: str, existing_values: Iterable[str]) -> bool:
    return any(value != existing and value in existing for existing in existing_values)


def extract_indicators(text: str) -> list[Indicator]:
    """Extract unique indicators while avoiding domain duplicates from URLs/emails."""

    found: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    high_context_values: list[str] = []

    for indicator_type, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = _clean_match(match.group(0))
            normalized = value.lower() if indicator_type in {"url", "email", "domain"} else value.lower()
            key = (indicator_type, normalized)

            if indicator_type == "domain" and _covered_by_existing(value.lower(), high_context_values):
                continue

            if key in seen:
                continue

            if indicator_type in {"url", "email"}:
                high_context_values.append(value.lower())

            seen.add(key)
            found.append(Indicator(type=indicator_type, value=value, defanged=defang(value)))

    return sorted(found, key=lambda item: (item.type, item.value.lower()))


def group_indicators(indicators: Iterable[Indicator]) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {name: [] for name in PATTERNS}
    for indicator in indicators:
        grouped[indicator.type].append(asdict(indicator))
    return grouped


def render_text(indicators: Iterable[Indicator]) -> str:
    lines = ["type,value,defanged"]
    lines.extend(f"{item.type},{item.value},{item.defanged}" for item in indicators)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract, defang, and refang indicators of compromise.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser("extract", help="Extract indicators from a UTF-8 text file.")
    extract_parser.add_argument("file", type=Path)
    extract_parser.add_argument("--format", choices=("json", "text"), default="json")
    extract_parser.add_argument("--grouped", action="store_true", help="Group JSON output by indicator type.")

    defang_parser = subparsers.add_parser("defang", help="Defang one indicator.")
    defang_parser.add_argument("value")

    refang_parser = subparsers.add_parser("refang", help="Refang one indicator.")
    refang_parser.add_argument("value")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "extract":
        text = args.file.read_text(encoding="utf-8")
        indicators = extract_indicators(text)
        if args.format == "text":
            print(render_text(indicators))
        elif args.grouped:
            print(json.dumps(group_indicators(indicators), indent=2, sort_keys=True))
        else:
            print(json.dumps([asdict(item) for item in indicators], indent=2, sort_keys=True))
    elif args.command == "defang":
        print(defang(args.value))
    elif args.command == "refang":
        print(refang(args.value))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
