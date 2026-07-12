"""Extract, normalize, defang, and refang common indicators of compromise."""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

TRAILING_PUNCTUATION = ".,;:)]}'\""
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
HASH_PATTERNS: dict[str, re.Pattern[str]] = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}
URL_CANDIDATE_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_CANDIDATE_RE = re.compile(
    r"\b[A-Z0-9._%+-]+(?:@|\[@\])[A-Z0-9.-]+(?:\.|\[\.\])[A-Z]{2,63}\b",
    re.IGNORECASE,
)
DOMAIN_CANDIDATE_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.|\[\.\]))+[a-z]{2,63}\b",
    re.IGNORECASE,
)
IPV4_CANDIDATE_RE = re.compile(r"\b(?:\d{1,3}(?:\.|\[\.\])){3}\d{1,3}\b")
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")


@dataclass(frozen=True, order=True)
class Indicator:
    """A normalized indicator extracted from text."""

    type: str
    value: str
    defanged: str
    source_form: str


def defang(value: str) -> str:
    """Return a safe-to-share representation of an indicator."""

    result = value.strip()
    result = re.sub(r"(?i)^https://", "hxxps://", result)
    result = re.sub(r"(?i)^http://", "hxxp://", result)
    result = result.replace("@", "[@]")
    result = result.replace(".", "[.]")
    return result


def refang(value: str) -> str:
    """Convert a common defanged indicator representation back to standard form."""

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


def _valid_domain(value: str) -> bool:
    candidate = value.lower().rstrip(".")
    if len(candidate) > 253 or "." not in candidate:
        return False
    labels = candidate.split(".")
    if len(labels[-1]) < 2 or labels[-1].isdigit():
        return False
    return all(DOMAIN_LABEL_RE.fullmatch(label) for label in labels)


def _valid_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            return False
        host = parsed.hostname
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return _valid_domain(host)
    except ValueError:
        return False


def _valid_email(value: str) -> bool:
    if value.count("@") != 1:
        return False
    local, domain = value.rsplit("@", 1)
    return bool(local) and len(local) <= 64 and _valid_domain(domain)


def _valid_ip(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


def _indicator_from_candidate(indicator_type: str, raw: str) -> Indicator | None:
    source_form = _clean_match(raw)
    value = refang(source_form)

    valid = {
        "url": _valid_url,
        "email": _valid_email,
        "domain": _valid_domain,
        "ipv4": lambda candidate: _valid_ip(candidate, 4),
        "ipv6": lambda candidate: _valid_ip(candidate, 6),
    }[indicator_type](value)
    if not valid:
        return None

    normalized = value.lower() if indicator_type in {"url", "email", "domain", "ipv6"} else value
    return Indicator(type=indicator_type, value=normalized, defanged=defang(normalized), source_form=source_form)


def extract_indicators(text: str) -> list[Indicator]:
    """Extract unique indicators from standard or commonly defanged text."""

    found: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    high_context_values: list[str] = []

    candidate_patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("url", URL_CANDIDATE_RE),
        ("email", EMAIL_CANDIDATE_RE),
        ("ipv4", IPV4_CANDIDATE_RE),
        ("ipv6", IPV6_CANDIDATE_RE),
        ("domain", DOMAIN_CANDIDATE_RE),
    )

    for indicator_type, pattern in candidate_patterns:
        for match in pattern.finditer(text):
            indicator = _indicator_from_candidate(indicator_type, match.group(0))
            if indicator is None:
                continue

            key = (indicator.type, indicator.value)
            if indicator.type == "domain" and _covered_by_existing(indicator.value, high_context_values):
                continue
            if key in seen:
                continue

            if indicator.type in {"url", "email"}:
                high_context_values.append(indicator.value)

            seen.add(key)
            found.append(indicator)

    for indicator_type, pattern in HASH_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0).lower()
            key = (indicator_type, value)
            if key in seen:
                continue
            seen.add(key)
            found.append(Indicator(type=indicator_type, value=value, defanged=value, source_form=match.group(0)))

    return sorted(found, key=lambda item: (item.type, item.value))


def group_indicators(indicators: Iterable[Indicator]) -> dict[str, list[dict[str, str]]]:
    keys = ("url", "email", "ipv4", "ipv6", "sha256", "sha1", "md5", "domain")
    grouped: dict[str, list[dict[str, str]]] = {name: [] for name in keys}
    for indicator in indicators:
        grouped[indicator.type].append(asdict(indicator))
    return grouped


def render_text(indicators: Iterable[Indicator]) -> str:
    return render_csv(indicators)


def render_csv(indicators: Iterable[Indicator]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["type", "value", "defanged", "source_form"])
    for item in indicators:
        writer.writerow([item.type, item.value, item.defanged, item.source_form])
    return output.getvalue().rstrip("\r\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract, normalize, defang, and refang indicators of compromise.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser("extract", help="Extract indicators from a UTF-8 text file.")
    extract_parser.add_argument("file", type=Path)
    extract_parser.add_argument("--format", choices=("json", "text", "csv"), default="json")
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
        if args.format in {"text", "csv"}:
            print(render_csv(indicators))
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
