import argparse
import json
import re
from pathlib import Path


HASH_PATTERNS = {
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

PATTERNS = {
    "urls": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "emails": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "domains": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE),
    **HASH_PATTERNS,
}


def defang(value: str) -> str:
    result = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    result = result.replace(".", "[.]")
    result = result.replace("@", "[@]")
    return result


def refang(value: str) -> str:
    result = value.replace("hxxps://", "https://").replace("hxxp://", "http://")
    result = result.replace("[.]", ".")
    result = result.replace("[@]", "@")
    return result


def extract_iocs(text: str) -> dict[str, list[str]]:
    extracted: dict[str, list[str]] = {}
    for name, pattern in PATTERNS.items():
        matches = sorted(set(match.group(0).rstrip(".,;:)") for match in pattern.finditer(text)))
        extracted[name] = matches
    return extracted


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract, defang, and refang indicators of compromise.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser("extract", help="Extract indicators from a text file.")
    extract_parser.add_argument("file", type=Path)

    defang_parser = subparsers.add_parser("defang", help="Defang one indicator.")
    defang_parser.add_argument("value")

    refang_parser = subparsers.add_parser("refang", help="Refang one indicator.")
    refang_parser.add_argument("value")

    args = parser.parse_args()

    if args.command == "extract":
        text = args.file.read_text(encoding="utf-8")
        print(json.dumps(extract_iocs(text), indent=2, sort_keys=True))
    elif args.command == "defang":
        print(defang(args.value))
    elif args.command == "refang":
        print(refang(args.value))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
