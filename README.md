# IOC Sanitizer

IOC Sanitizer is a defensive Python command-line utility for extracting, validating, normalizing, defanging, and refanging indicators of compromise from analyst notes and sanitized reports.

## Supported Indicators

- URLs, including commonly defanged `hxxp` and `hxxps` forms
- Domains, including `[.]` notation
- IPv4 addresses
- IPv6 addresses
- Email addresses, including `[@]` notation
- MD5, SHA-1, and SHA-256 hashes

## Features

- Extracts standard and commonly defanged indicators.
- Normalizes indicators before deduplication.
- Validates IP addresses with Python's `ipaddress` module.
- Validates URL hostnames and domain labels before reporting them.
- Avoids duplicate domain findings when the domain is already present in a URL or email.
- Produces flat JSON, grouped JSON, and RFC-compatible CSV output.
- Preserves the original matched form in `source_form` for analyst traceability.
- Uses only the Python standard library.

## Usage

```bash
python ioc_sanitizer.py extract sample.txt
python ioc_sanitizer.py extract sample.txt --grouped
python ioc_sanitizer.py extract sample.txt --format csv
python ioc_sanitizer.py defang "https://example.com/login?x=1"
python ioc_sanitizer.py refang "hxxps://example[.]com/login"
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

## Run Tests

```bash
python -m unittest -v
```

The repository currently contains 13 unit and CLI tests.

## Continuous Integration

GitHub Actions runs the test suite on every push and pull request against Python 3.10, 3.11, and 3.12.

## Current Limitations

- IOC extraction is deterministic and pattern-based; findings still require analyst validation.
- Internationalized domain names are not normalized to or from Punycode.
- The tool does not perform reputation lookups or enrichment.
- STIX export is not yet implemented.

## Safety

Do not upload private incident data, credentials, tokens, customer logs, or unredacted malware reports to a public repository.
