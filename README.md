# IOC Sanitizer

Extract, defang, and refang common indicators of compromise from text.

This is a defensive blue-team utility for safely sharing suspicious domains, URLs, IP addresses, hashes, and email addresses in reports.

## Features

- Extracts IPv4 addresses, domains, URLs, emails, MD5, SHA1, and SHA256 hashes.
- Defangs indicators for safe sharing.
- Refangs defanged indicators back into usable form.
- Runs without third-party dependencies.

## Usage

```bash
python ioc_sanitizer.py extract sample.txt
python ioc_sanitizer.py defang "https://example.com/login?x=1"
python ioc_sanitizer.py refang "hxxps://example[.]com/login"
```

## Run Tests

```bash
python -m unittest test_ioc_sanitizer.py
```

## Safety Note

Do not open suspicious URLs or submit private incident data to public repositories.
