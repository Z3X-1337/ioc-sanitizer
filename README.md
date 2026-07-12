# IOC Sanitizer

[![tests](https://github.com/Z3X-1337/ioc-sanitizer/actions/workflows/tests.yml/badge.svg)](https://github.com/Z3X-1337/ioc-sanitizer/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/Python-3.10--3.12-blue)
![Version](https://img.shields.io/badge/version-0.1.0-informational)
![License](https://img.shields.io/badge/license-MIT-green)

IOC Sanitizer is a deterministic, local Python command-line utility for extracting, validating, normalizing, defanging, and refanging indicators of compromise from analyst notes and sanitized reports.

## Supported Indicators

- URLs, including commonly defanged `hxxp` and `hxxps` forms.
- Domains, including `[.]` notation.
- IPv4 addresses.
- IPv6 addresses.
- Email addresses, including `[@]` notation.
- MD5, SHA-1, and SHA-256 hashes.

## Features

- Extracts standard and commonly defanged indicators.
- Normalizes indicators before deduplication.
- Validates IP addresses with Python's `ipaddress` module.
- Validates URL hostnames and domain labels before reporting them.
- Avoids duplicate domain findings when the domain is already present in a URL or email.
- Produces flat JSON, grouped JSON, and RFC-compatible CSV output.
- Preserves the original matched form in `source_form` for analyst traceability.
- Uses only the Python standard library.

## Installation

Install from a local clone:

```bash
python -m pip install .
```

For an isolated CLI installation:

```bash
pipx install .
```

The installed command is:

```bash
ioc-sanitizer --help
```

## Usage

```bash
ioc-sanitizer extract sample.txt
ioc-sanitizer extract sample.txt --grouped
ioc-sanitizer extract sample.txt --format csv
ioc-sanitizer defang "https://example.com/login?x=1"
ioc-sanitizer refang "hxxps://example[.]com/login"
```

The source-file form remains supported:

```bash
python ioc_sanitizer.py extract sample.txt
```

## Example Output

```json
{
  "defanged": "203[.]0[.]113[.]24",
  "source_form": "203.0.113.24",
  "type": "ipv4",
  "value": "203.0.113.24"
}
```

## Validation

```bash
python -m unittest -v
```

The repository currently contains 13 unit and CLI tests. GitHub Actions tests Python 3.10, 3.11, and 3.12, installs the package, and verifies the CLI entry point.

## Project Governance

- [Changelog](CHANGELOG.md)
- [Roadmap](ROADMAP.md)
- [MIT License](LICENSE)

The current package version is `0.1.0` and follows Semantic Versioning.

## Current Limitations

- IOC extraction is deterministic and pattern-based; findings still require analyst validation.
- Internationalized domain names are not normalized to or from Punycode.
- The tool does not perform reputation lookups or enrichment.
- STIX export is not yet implemented.

## Safety

Do not upload private incident data, credentials, tokens, customer logs, or unredacted malware reports to a public repository.
