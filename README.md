# IOC Sanitizer

IOC Sanitizer is a defensive Python command-line utility for extracting, normalizing, defanging, and refanging common indicators of compromise.

It is designed for safe reporting workflows where analysts need to share suspicious URLs, domains, IP addresses, email addresses, and hashes without accidentally creating clickable or active indicators.

## Supported Indicators

- URLs
- Domains
- IPv4 addresses
- Email addresses
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

## Features

- Produces structured JSON output by default.
- Supports grouped JSON and text output.
- Defangs indicators for safe reports.
- Refangs indicators when a standard representation is needed.
- Deduplicates case-insensitive URL, email, and domain matches.
- Avoids duplicate domain extraction when the domain is already part of a URL or email.
- Uses only the Python standard library.

## Usage

```bash
python ioc_sanitizer.py extract sample.txt
python ioc_sanitizer.py extract sample.txt --grouped
python ioc_sanitizer.py extract sample.txt --format text
python ioc_sanitizer.py defang "https://example.com/login?x=1"
python ioc_sanitizer.py refang "hxxps://example[.]com/login"
```

## Example Output

```json
[
  {
    "defanged": "198[.]51[.]100[.]24",
    "type": "ipv4",
    "value": "198.51.100.24"
  }
]
```

## Run Tests

```bash
python -m unittest -v
```

## Continuous Integration

The repository includes a GitHub Actions workflow that runs the test suite on every push and pull request.

## Safety

Do not upload private incident data, credentials, tokens, customer logs, or unredacted malware reports to a public repository.
